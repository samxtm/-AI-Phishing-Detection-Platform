from database.database import (
    initialize_database,
    create_user,
    authenticate_user,
    save_scan,
    get_user_scans
)


print("=" * 50)
print("USER DATABASE TEST")
print("=" * 50)


# Initialize database

initialize_database()

print("Database initialized.")


# Create test user

created = create_user(
    "testuser",
    "test123"
)

print(
    "User created:",
    created
)


# Login test

user = authenticate_user(
    "testuser",
    "test123"
)

print(
    "Login result:",
    user
)


# Save test scan

if user:

    save_scan(
        user_id=user["id"],
        scan_time="2026-08-23 20:00:00",
        scan_type="Email",
        target="Test Email",
        risk_score=80,
        risk_level="HIGH RISK",
        findings_count=5
    )

    print("Test scan saved.")


# Read scans

if user:

    scans = get_user_scans(
        user["id"]
    )

    print(
        "User scan count:",
        len(scans)
    )


print("=" * 50)
print("DATABASE TEST COMPLETE")
print("=" * 50)