//! Prints the ClickHouse schema, one statement per line, so CI can create
//! it on a real server before the dashboards' queries run (ADR 0041).

fn main() {
    for (_, statement) in tidegard_storage::schema::CREATE_TABLE_STATEMENTS {
        println!("{statement}");
    }
}
