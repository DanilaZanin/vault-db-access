import clickhouse_connect
import psycopg2

from . import config, secrets_store


def list_postgres_tables() -> list[str]:
    conn = psycopg2.connect(
        host=config.POSTGRES_HOST,
        port=config.POSTGRES_PORT,
        user=config.POSTGRES_INTROSPECT_USER,
        password=secrets_store.postgres_introspect_password(),
        dbname=config.POSTGRES_DB,
    )
    try:
        with conn.cursor() as cur:
            # pg_catalog.pg_tables (unlike information_schema.tables) is not filtered by
            # the querying role's privileges, so the minimal-privilege introspect account
            # can still see table names without being granted SELECT on any of them.
            cur.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' ORDER BY tablename")
            return [row[0] for row in cur.fetchall()]
    finally:
        conn.close()


def list_clickhouse_tables() -> list[str]:
    client = clickhouse_connect.get_client(
        host=config.CLICKHOUSE_HOST,
        port=config.CLICKHOUSE_HTTP_PORT,
        username=config.CLICKHOUSE_INTROSPECT_USER,
        password=secrets_store.clickhouse_introspect_password(),
    )
    result = client.query(
        "SELECT name FROM system.tables WHERE database = %(db)s ORDER BY name",
        parameters={"db": config.CLICKHOUSE_DB},
    )
    return [row[0] for row in result.result_rows]
