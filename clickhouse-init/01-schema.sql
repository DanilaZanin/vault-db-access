CREATE DATABASE IF NOT EXISTS appdb;

CREATE TABLE IF NOT EXISTS appdb.customers (
    id UInt32,
    name String,
    email String
) ENGINE = MergeTree ORDER BY id;

CREATE TABLE IF NOT EXISTS appdb.products (
    id UInt32,
    name String,
    price Decimal(10, 2)
) ENGINE = MergeTree ORDER BY id;

CREATE TABLE IF NOT EXISTS appdb.orders (
    id UInt32,
    customer_id UInt32,
    product_id UInt32,
    quantity UInt32
) ENGINE = MergeTree ORDER BY id;

INSERT INTO appdb.customers VALUES (1, 'Alice Ivanova', 'alice@example.com'), (2, 'Boris Petrov', 'boris@example.com');
INSERT INTO appdb.products VALUES (1, 'Widget', 9.99), (2, 'Gadget', 19.99);
INSERT INTO appdb.orders VALUES (1, 1, 1, 3), (2, 2, 2, 1);
