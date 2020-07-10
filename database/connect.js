const mongoose = require('mongoose');

async function connect() {
    try {
        const connection = await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        })

        console.log('Connected to MongoDB');

        return connection;
    } catch (err) {
        throw new Error(err);
    }
}

module.exports = connect;