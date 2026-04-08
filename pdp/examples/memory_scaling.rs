//! Memory scaling measurement for Cedar policy sets, entity sets, and schema parsing.
//!
//! Run with: cargo run --example memory_scaling --release

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashSet;
use std::hint::black_box;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use cedar_policy::{
    Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Schema,
};

// --- Tracking allocator ---

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

struct TrackingAlloc;

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static GLOBAL: TrackingAlloc = TrackingAlloc;

fn current_allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed)
}

// --- Helpers ---

fn make_uid(type_name: &str, id: &str) -> EntityUid {
    let tn = EntityTypeName::from_str(type_name).expect("valid type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

const SIMPLE_SCHEMA: &str = r#"
entity User;
entity Resource;
action "read" appliesTo { principal: [User], resource: [Resource] };
"#;

const PROD_SCHEMA: &str = include_str!("../../policies/api_gateway.cedarschema");

/// Generate N permit policies as a string and parse into a PolicySet.
fn make_policy_set(n: usize) -> PolicySet {
    let mut src = String::with_capacity(n * 100);
    for i in 0..n {
        src.push_str(&format!(
            "permit(principal == User::\"user-{i}\", action == Action::\"read\", resource == Resource::\"/r-{i}\");\n"
        ));
    }
    src.parse::<PolicySet>().expect("valid policy set")
}

/// Generate N User entities with attributes.
fn make_entities(n: usize) -> Entities {
    let mut entity_vec: Vec<Entity> = Vec::with_capacity(n * 2);
    for i in 0..n {
        let uid = make_uid("User", &format!("user-{i}"));
        entity_vec.push(Entity::new_no_attrs(uid, HashSet::new()));
    }
    for i in 0..n {
        let uid = make_uid("Resource", &format!("/r-{i}"));
        entity_vec.push(Entity::new_no_attrs(uid, HashSet::new()));
    }
    Entities::from_entities(entity_vec, None).expect("valid entities")
}

/// Measure bytes allocated by a closure (delta between before and after).
fn measure_alloc<F, T>(f: F) -> (T, usize)
where
    F: FnOnce() -> T,
{
    let before = current_allocated();
    let result = f();
    let after = current_allocated();
    // Saturating because concurrent allocations or measurement noise can cause underflow
    let delta = after.saturating_sub(before);
    (result, delta)
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn main() {
    let counts = [10, 100, 1_000, 5_000, 10_000];

    // --- PolicySet scaling ---
    println!("=== PolicySet Memory Scaling ===");
    println!("{:<10} {:>15} {:>15}", "Policies", "Bytes", "Human");
    println!("{:-<10} {:-<15} {:-<15}", "", "", "");
    for &n in &counts {
        let (ps, delta) = measure_alloc(|| make_policy_set(n));
        let _ = black_box(ps);
        println!("{:<10} {:>15} {:>15}", n, delta, format_bytes(delta));
    }

    println!();

    // --- Entity scaling ---
    println!("=== Entity Set Memory Scaling ===");
    println!("{:<10} {:>15} {:>15}", "Entities", "Bytes", "Human");
    println!("{:-<10} {:-<15} {:-<15}", "", "", "");
    for &n in &counts {
        let (ent, delta) = measure_alloc(|| make_entities(n));
        let _ = black_box(ent);
        println!("{:<10} {:>15} {:>15}", n * 2, delta, format_bytes(delta));
    }

    println!();

    // --- Schema parsing ---
    println!("=== Schema Parsing Memory ===");
    println!("{:<25} {:>15} {:>15}", "Schema", "Bytes", "Human");
    println!("{:-<25} {:-<15} {:-<15}", "", "", "");

    let (s1, delta1) = measure_alloc(|| {
        Schema::from_cedarschema_str(SIMPLE_SCHEMA).expect("valid simple schema").0
    });
    let _ = black_box(s1);
    println!("{:<25} {:>15} {:>15}", "simple (2 entities)", delta1, format_bytes(delta1));

    let (s2, delta2) = measure_alloc(|| {
        Schema::from_cedarschema_str(PROD_SCHEMA).expect("valid prod schema").0
    });
    let _ = black_box(s2);
    println!("{:<25} {:>15} {:>15}", "production (ApiGateway)", delta2, format_bytes(delta2));
}
