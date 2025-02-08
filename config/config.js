require('dotenv').config();

const config = {
    port: process.env.PORT || 4000,
    jwtSecret: process.env.JWT_SECRET,
    database: {
        url: process.env.DATABASE_URL
    },
    env: process.env.NODE_ENV || 'development'
};

module.exports = config;




