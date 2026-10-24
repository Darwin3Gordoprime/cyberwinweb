import pg from 'pg';

const { Pool } = pg;

export function createDatabasePool() {
    const ssl = process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: true } : false;
    const connectionString = process.env.DATABASE_URL;
    if (connectionString) return new Pool({ connectionString, ssl });

    const host = process.env.DB_HOST;
    const database = process.env.DB_NAME;
    const user = process.env.DB_USER;
    const password = process.env.DB_PASSWORD;
    if (!host || !database || !user || !password) {
        throw new Error('Set DATABASE_URL or DB_HOST, DB_NAME, DB_USER and DB_PASSWORD in .env.');
    }

    const port = Number(process.env.DB_PORT || 5432);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('DB_PORT must be a valid TCP port.');
    }

    return new Pool({ host, port, database, user, password, ssl });
}
