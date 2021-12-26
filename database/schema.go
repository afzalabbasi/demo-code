package database

var (
	// Database schema setup queries
	dbSchema = []string{
		// Put schema queries here!
		"CREATE TABLE IF NOT EXISTS users (_id serial not null, advisorid int,firstname VARCHAR, lastname VARCHAR, email VARCHAR PRIMARY KEY, password VARCHAR, isverified bool, urole int, isadvisor bool, onleave bool, parentemail VARCHAR, age int, haveconcent bool, create_date Date, update_date Date)",
	}
)
