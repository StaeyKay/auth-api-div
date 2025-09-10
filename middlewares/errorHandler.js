export const errorHandler = (err, req, res, next) => {
    let statusCode = err.statusCode || 500;

    let message = err.message;

    if(err.code === 11000) {
        statusCode = 409; //conflict
        const msg = Object.values(err.keyValue).join(', ');
        message = `${msg} already exists`
    }

    res.status(statusCode).json({
        success: false,
        message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : null
    })
}