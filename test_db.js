// test_db.js (run with node test_db.js)
const mysql = require('mysql2/promise');

const dbConfig = { 
  host: 'srv1267.hstgr.io', 
  user: 'u418580423_rootie', 
  password: '0Idontknow0$%$%', 
  database: 'u418580423_scm_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

async function testConnection() {
  const pool = mysql.createPool(dbConfig);
  try {
    const connection = await pool.getConnection();
    console.log('✅ Connected to DB!');
    connection.release();
  } catch (error) {
    console.error('❌ Connection error:', error.message);
  } finally {
    pool.end();
  }
}

testConnection();