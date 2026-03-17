#!/bin/bash
# Setup script for MSSQL test database
# Run after docker compose up when MSSQL is healthy
#
# Creates test user and database for Argus E2E testing

echo "Waiting for MSSQL to be ready..."
sleep 10

docker compose exec mssql /opt/mssql-tools18/bin/sqlcmd \
    -S localhost -U sa -P 'Argus_Pass123!' -C -N \
    -Q "
    IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'testdb')
    BEGIN
        CREATE DATABASE testdb;
    END;
    GO

    USE testdb;
    GO

    IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'argus_test')
    BEGIN
        CREATE LOGIN argus_test WITH PASSWORD = 'Argus_Pass123!';
    END;
    GO

    IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'argus_test')
    BEGIN
        CREATE USER argus_test FOR LOGIN argus_test;
        ALTER ROLE db_owner ADD MEMBER argus_test;
    END;
    GO

    PRINT 'MSSQL test database setup complete';
    "

echo "MSSQL setup done."
