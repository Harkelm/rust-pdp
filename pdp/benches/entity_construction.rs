//! Entity construction benchmarks -- measures the cost of building Cedar
//! entities from JWT claims, which is the hot path for every authorization
//! request through the claims path.
//!
//! This is a critical path cost that does not appear in the cedar_eval
//! benchmarks (which pre-build entities). At agent scale, entity construction
//! runs per-request and its cost is additive to Cedar evaluation.

use cedar_policy::Schema;
use cedar_pdp::entities::{build_entities, build_request_uids, Claims, RequestContext};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const PROD_SCHEMA: &str = include_str!("../../policies/api_gateway.cedarschema");

fn prod_schema() -> Schema {
    Schema::from_cedarschema_str(PROD_SCHEMA)
        .expect("valid schema")
        .0
}

fn make_claims(n_roles: usize, n_scopes: usize) -> Claims {
    Claims {
        sub: "bench-user".to_string(),
        email: Some("bench@example.com".to_string()),
        department: Some("engineering".to_string()),
        org: Some("acme".to_string()),
        roles: Some((0..n_roles).map(|i| format!("role-{i}")).collect()),
        subscription_tier: Some("enterprise".to_string()),
        suspended: Some(false),
        allowed_scopes: Some((0..n_scopes).map(|i| format!("scope-{i}")).collect()),
    }
}

fn make_request_ctx() -> RequestContext {
    RequestContext {
        method: "GET".to_string(),
        path: "/api/v1/data".to_string(),
        service: Some("user-service".to_string()),
    }
}

fn bench_build_entities(c: &mut Criterion) {
    let mut group = c.benchmark_group("entity_construction");
    let schema = prod_schema();
    let ctx = make_request_ctx();

    // Baseline: typical production claims (2 roles, 2 scopes)
    {
        let claims = Claims {
            sub: "typical-user".to_string(),
            email: Some("user@example.com".to_string()),
            department: Some("engineering".to_string()),
            org: Some("acme".to_string()),
            roles: Some(vec!["editor".to_string(), "viewer".to_string()]),
            subscription_tier: Some("professional".to_string()),
            suspended: Some(false),
            allowed_scopes: Some(vec!["internal".to_string(), "public".to_string()]),
        };
        group.bench_function("typical_2roles_2scopes", |b| {
            b.iter(|| build_entities(&claims, &ctx, Some(&schema)));
        });
    }

    // Minimal: sub-only claims
    {
        let claims = Claims {
            sub: "minimal".to_string(),
            ..Default::default()
        };
        group.bench_function("minimal_sub_only", |b| {
            b.iter(|| build_entities(&claims, &ctx, None));
        });
    }

    // Scaling: increasing role count
    for n_roles in [1usize, 5, 10, 20, 50] {
        let claims = make_claims(n_roles, 2);
        group.bench_function(BenchmarkId::new("roles", n_roles), |b| {
            b.iter(|| build_entities(&claims, &ctx, Some(&schema)));
        });
    }

    // Scaling: increasing scope count
    for n_scopes in [1usize, 5, 10, 20, 50] {
        let claims = make_claims(2, n_scopes);
        group.bench_function(BenchmarkId::new("scopes", n_scopes), |b| {
            b.iter(|| build_entities(&claims, &ctx, Some(&schema)));
        });
    }

    group.finish();
}

fn bench_build_request_uids(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_uid_construction");

    let claims = Claims {
        sub: "bench-user".to_string(),
        ..Default::default()
    };

    for method in &["GET", "POST", "DELETE"] {
        let ctx = RequestContext {
            method: method.to_string(),
            path: "/api/v1/data".to_string(),
            service: None,
        };
        group.bench_function(*method, |b| {
            b.iter(|| build_request_uids(&claims, &ctx));
        });
    }

    group.finish();
}

/// End-to-end entity construction + Cedar eval to show the full per-request cost.
fn bench_full_request_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_request_pipeline");
    let schema = prod_schema();

    let combined_src = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        include_str!("../../policies/rbac_route_access.cedar"),
        include_str!("../../policies/subscription_tier_gating.cedar"),
        include_str!("../../policies/org_scoped_access.cedar"),
        include_str!("../../policies/suspended_account_deny.cedar"),
        include_str!("../../policies/template_resource_access.cedar"),
        include_str!("../../policies/data_scope_access.cedar"),
    );
    let policies: cedar_policy::PolicySet = combined_src.parse().expect("valid policies");
    let authorizer = cedar_policy::Authorizer::new();

    // Typical admin request: entity construction + evaluation
    let claims = Claims {
        sub: "pipeline-admin".to_string(),
        email: Some("admin@example.com".to_string()),
        department: Some("engineering".to_string()),
        org: Some("acme".to_string()),
        roles: Some(vec!["admin".to_string()]),
        subscription_tier: Some("enterprise".to_string()),
        suspended: Some(false),
        allowed_scopes: Some(vec!["internal".to_string()]),
    };
    let ctx = RequestContext {
        method: "GET".to_string(),
        path: "/api/v1/users".to_string(),
        service: None,
    };

    group.bench_function("admin_read_e2e", |b| {
        b.iter(|| {
            let entities = build_entities(&claims, &ctx, Some(&schema)).unwrap();
            let (principal, action, resource) = build_request_uids(&claims, &ctx).unwrap();
            let request = cedar_policy::Request::new(
                principal,
                action,
                resource,
                cedar_policy::Context::empty(),
                Some(&schema),
            )
            .unwrap();
            authorizer.is_authorized(&request, &policies, &entities)
        });
    });

    // Suspended user: entity construction + evaluation (forbid path)
    let suspended_claims = Claims {
        sub: "pipeline-suspended".to_string(),
        email: Some("sus@example.com".to_string()),
        department: Some("engineering".to_string()),
        org: Some("acme".to_string()),
        roles: Some(vec!["admin".to_string()]),
        subscription_tier: Some("enterprise".to_string()),
        suspended: Some(true),
        allowed_scopes: Some(vec!["internal".to_string()]),
    };

    group.bench_function("suspended_deny_e2e", |b| {
        b.iter(|| {
            let entities = build_entities(&suspended_claims, &ctx, Some(&schema)).unwrap();
            let (principal, action, resource) = build_request_uids(&suspended_claims, &ctx).unwrap();
            let request = cedar_policy::Request::new(
                principal,
                action,
                resource,
                cedar_policy::Context::empty(),
                Some(&schema),
            )
            .unwrap();
            authorizer.is_authorized(&request, &policies, &entities)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_build_entities,
    bench_build_request_uids,
    bench_full_request_pipeline
);
criterion_main!(benches);
