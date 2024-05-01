export const configuration = {
    user: 'user',
    host: 'localhost',
    database: 'signatures',
    password: '1',
    port: 5432
}

/*
В самой таблице data:
    поле hash: 
        тип: text
        NOT NULL, PRIMARY KEY
    поле public_key:
        тип: text
        NOT NULL
*/