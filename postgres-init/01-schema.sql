-- Sample schema for testing scoped Vault-issued DB access.
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    price NUMERIC(10, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL
);

INSERT INTO customers (name, email) VALUES
    ('Alice Ivanova', 'alice@example.com'),
    ('Boris Petrov', 'boris@example.com');

INSERT INTO products (name, price) VALUES
    ('Widget', 9.99),
    ('Gadget', 19.99);

INSERT INTO orders (customer_id, product_id, quantity) VALUES
    (1, 1, 3),
    (2, 2, 1);
