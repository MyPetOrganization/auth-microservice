import { IsString, IsEmail, IsIn, MinLength } from 'class-validator';
import { Transform } from "class-transformer";

/**
 * Data transfer object for registering a new user.
 */
export class RegisterUserDto {

  /**
   * The name of the user.
   * Verify that the name is a string.
   */
  @IsString()
  public name: string;

  /**
   * The email of the user.
   * Verify that the email is a valid email.
   */
  @IsEmail()
  public email: string;

  /**
   * The password of the user.
   * Verify that the password is a string.
   * Verify that the password is at least 8 characters long.
   */
  @Transform(({ value }) => value.trim())
  @IsString()
  @MinLength(8, {
    message: 'password must be at least 8 characters'
  })
  public password: string;

  /**
   * The secret question of the user.
   * Verify that the secret question (favorite movie) is a string.
   */
  @Transform(({ value }) => value.trim())
  @IsString()
  @MinLength(1)
  public favoriteMovie: string;

  /**
   * The role of the user.
   * Verify that the role is a string.
   * Verify that the role is either 'admin', 'buyer', or 'seller'.
   */
  @IsString()
  @IsIn(['admin', 'buyer', 'seller'])
  public role: string;
}
