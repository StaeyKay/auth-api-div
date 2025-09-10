import mongoose from "mongoose";

const uri = process.env.MONGO_URI;


async function dbConnection() {
    try {
        await mongoose.connect(uri);
        console.log('Database is connected')
    } catch (error) {
        console.log(error)
    }
}

export default dbConnection;