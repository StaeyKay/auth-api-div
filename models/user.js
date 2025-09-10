import { Schema, model } from "mongoose";
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const userSchema = new Schema({
    firstName: {type: String, required: true},
    lastName: {type: String, required: true},
    email: {
        type: String, 
        required: true, 
        unique: true,
        validate: {
            validator: function(value){
                return value.includes('@')
            },
            message: (props) => `${props.value} is not a valid email`
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 5
    },
    resetPasswordToken: String,
    resetPasswordTokenExpiry: Date
,
},
{timestamps: true});

userSchema.pre('save', async function(next){
    if(!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 10);
    next()
});

userSchema.methods.comparePassword = function(password, dbPassword) {
    return bcrypt.compare(password, dbPassword);
}

userSchema.methods.generatePasswordResetToken = function() {
    const resetToken = crypto.randomBytes(16).toString('hex');
    this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    this.resetPasswordTokenExpiry = Date.now() + 7 * 6 * 1000;

    return resetToken;
}

const User = model('User', userSchema);

export default User;

