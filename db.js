require('dotenv/config');
var mysql = require('mysql');
var pool = mysql.createPool({
	connectionLimit: 10,
	host: 	  process.env.DB_HOST,
	user: 	  process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
	port: 	  process.env.DB_PORT,
    debug: 	  false,
    timezone: 'utc'
});

module.exports = pool;
