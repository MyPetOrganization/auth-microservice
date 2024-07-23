import { Transform } from "class-transformer";
import { IsEmail, IsIn, IsString, MinLength } from "class-validator";

/**
 * Data transfer object so that a user can log in.
 */
export class LoginUserDto {
  
    /**
     * The email of the user.
     * Verify that the email is a valid email.
     */
    @IsString()
    @IsEmail()
    email: string;

    /**
     * The password of the user.
     * Verify that the password is a string.
     * Verify that the password is at least 8 characters long.
     */
    @Transform(({ value }) => value.trim())
    @IsString()
    @MinLength(8,{
        message: 'password must be at least 8 characters'
    })
    password: string;

    /**
     * The role of the user.
     * Verify that the role is a string
     * Verify that the role is either 'admin', 'buyer', or 'seller'.
     */
    @IsString()
    @IsIn(['admin', 'buyer', 'seller'])
    role: string;
}