import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginUserDto, RegisterUserDto } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * 
   * @param loginUserDto - The user's login information.
   * @returns The user data and token.
   */
  @MessagePattern({ cmd: 'auth_login_user' })
  async loginUser(@Payload() loginUserDto: LoginUserDto) {
    return this.authService.loginUser(loginUserDto);
  }


  @MessagePattern({ cmd: 'auth_reset_passwotd' })
  async resetPassword(@Payload() email:string, password: string, favoriteMovie: string) {
    return this.authService.resetPassword(email, password, favoriteMovie);
  }

  /**
   * 
   * @param registerUserDto - The user's registration information.
   * @returns The user data and token.
   */
  @MessagePattern({ cmd: 'auth_register_user' })
  async registerUser(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.registerUser(registerUserDto);
  }

  /**
   * 
   * @param payload - The token to verify.
   * @returns The result of the token verification.
   */
  @MessagePattern({ cmd: 'auth_verify_user' })
  async verifyToken(@Payload() payload: any){
    // Deep copy the payload to avoid mutation
    payload = JSON.parse(JSON.stringify(payload));
    // Extract the token from the payload
    const token = payload.token;
    return this.authService.verifyToken(token);
  }
}
