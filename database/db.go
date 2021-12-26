package database

import "github.com/jmoiron/sqlx"

type DB struct {
	*sqlx.DB
}

func Connect(driverName, dataSourceName string) (*DB, error) {
	db, err := sqlx.Connect(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (db *DB) Init() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	for _, query := range dbSchema {
		_, err = tx.Exec(query)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}
