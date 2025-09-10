import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import morgan from 'morgan';
import dbConnection from './config/db.js';
import userRouter from './routes/authRoutes.js';
import { errorHandler } from './middlewares/errorHandler.js';

const PORT = process.env.PORT || 5050;

const app = express();

// Apply middlewares
app.use(express.json());
app.use(cookieParser()); // allows us to view/access the cookies that come with the request
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}));

if(process.env.NODE_ENV === 'development') {
    app.use(morgan('common'));
}

// Use routes
app.use('/api/auth', userRouter);

app.use(errorHandler);

// Connect to database
dbConnection()

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`)
});