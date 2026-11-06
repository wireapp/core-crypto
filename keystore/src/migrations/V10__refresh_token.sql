CREATE TABLE e2ei_refresh_token (
    id INTEGER PRIMARY KEY CHECK ( id = 0 ),
    content BLOB
);
