import 'dotenv/config';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createDatabasePool } from '../db/pool.js';

try {
    const pool = createDatabasePool();
    const migrationsDirectory = fileURLToPath(new URL('../db/migrations/', import.meta.url));
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_name TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);
        const migrations = (await readdir(migrationsDirectory))
            .filter(file => /^\d+_[\w-]+\.sql$/.test(file))
            .sort();
        for (const file of migrations) {
            const alreadyApplied = await client.query(
                'SELECT 1 FROM schema_migrations WHERE migration_name = $1',
                [file]
            );
            if (alreadyApplied.rowCount) {
                console.log(`Skipped ${file}; already applied.`);
                continue;
            }
            const migration = await readFile(new URL(`../db/migrations/${file}`, import.meta.url), 'utf8');
            await client.query('BEGIN');
            try {
                await client.query(migration);
                await client.query('INSERT INTO schema_migrations (migration_name) VALUES ($1)', [file]);
                await client.query('COMMIT');
                console.log(`Applied ${file}.`);
            } catch (error) {
                await client.query('ROLLBACK');
                throw error;
            }
        }
        console.log('Database schema migration completed.');
    } finally {
        client.release();
        await pool.end();
    }
} catch (error) {
    console.error('Database migration failed:', error.message);
    process.exitCode = 1;
}
