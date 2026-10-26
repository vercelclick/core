use secretpass_api::projects::CreateEnvironmentRequest;
use secretpass_core::SpassProject;
use sqlx::{Postgres, QueryBuilder};

// language=sql
const CREATE_ENVIRONMENTS_QUERY: &str =
    r#"INSERT INTO "Environments" (name, project_id, description) "#;

pub fn environments_insert_query_builder(
    project: &SpassProject,
    requests: &Vec<CreateEnvironmentRequest>,
) -> QueryBuilder<Postgres> {
    let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(CREATE_ENVIRONMENTS_QUERY);

    query_builder.push_values(requests, |mut b, request| {
        b.push_bind(request.name.clone())
            .push_bind(project.id)
            .push_bind(request.description.clone());
    });

    query_builder.push(" RETURNING *");

    query_builder
}
