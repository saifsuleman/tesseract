import mysql, { FieldInfo } from "mysql";
import dotenv from "dotenv";

dotenv.config();

export class Database {
  pool: mysql.Pool;

  constructor(
    host: string,
    user: string,
    password: string,
    database: string,
    connectionLimit = 10
  ) {
    this.pool = mysql.createPool({
      host,
      user,
      password,
      database,
      connectionLimit,
    });
  }

  query(data: QueryOptions | string): mysql.Query {
    if (!(<any>data).query) {
      data = { query: data } as QueryOptions;
    }
    let { query, params, callback } = data as QueryOptions;
    if (params) {
      query = mysql.format(query, params);
    }
    return this.pool.query(query, (err, results, fields) => {
      if (err) throw err;
      if (callback) callback(results, fields);
    });
  }
}

export interface QueryOptions {
  query: string;
  params?: any[];
  callback?: (results?: any, fields?: FieldInfo[]) => void;
}

const { host, user, password, database } = process.env as {
  host: string;
  user: string;
  password: string;
  database: string;
};
export default new Database(host, user, password, database);
