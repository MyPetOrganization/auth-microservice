import { Inject, Injectable } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import * as dotenv from 'dotenv';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcryptjs';
import { firstValueFrom } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

// Load environment variables from .env file
dotenv.config();

@Injectable()
export class AuthService {
    constructor(
        @Inject(process.env.NATS) private readonly userClient: ClientProxy,
        private readonly jwtService: JwtService
    ) { }

    /**
     * 
     * @param payload - The payload to sign into a JWT token.
     * @returns The signed JWT token.
     */
    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    /**
     * 
     * @param token - The token to verify.
     * @returns The result of the token verification.
     * @throws RpcException if the token is invalid.
     * @throws RpcException if the token is expired.
     * @throws RpcException if the token is not found.
     */
    async verifyToken(token: string) {
        try {
            // Extract the user data from the token
            const { sub, iat, exp, ...user} = await this.jwtService.verify(token);

            // Return the user data and a new token
            return {
                user: user,
                token: await this.signJWT(user)
            }
        } catch (e) {
            // If the token is invalid, throw an error
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            });
        }
    }

    /**
     * 
     * @param registerUserDto - The user's registration information.
     * @returns The user data and token.
     * @throws RpcException if the user already exists.
     * @throws RpcException if the user creation fails.
     */
    async registerUser(registerUserDto: RegisterUserDto) {
        // Extract the email from the registration data
        const email = registerUserDto.email;

        try {
            // Check if the user already exists
            const user = await firstValueFrom(this.userClient.send({ cmd: 'get_user_by_email' }, {email}));
            // If the user exists, throw an error
            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }
            // Converting the information into a payload
            const payload: any = {
                createUserDto: registerUserDto,
                image: null,
            };
            return this.userClient.send({ cmd: 'create_user' }, payload);
        } catch (e) {
            // If the user creation fails, throw an error
            throw new RpcException({
                status: 400,
                message: e.message
            })
        }
    }

    /**
     * 
     * @param loginUserDto - The user's login information.
     * @returns The user data and token.
     * @throws RpcException if the user/password is incorrect.
     * @throws RpcException if the user/role is not suitable.
     */
    async loginUser(loginUserDto: LoginUserDto) {
        const email = loginUserDto.email;

        try {
            // Check if the user exists
            const user = await firstValueFrom(this.userClient.send({ cmd: 'get_user_by_email' }, {email}));

            // If the user does not exist, throw an error
            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }
            // Check if the password is valid
            const isPasswordValid = await bcrypt.compareSync(loginUserDto.password, user.password);
            // If the password is invalid, throw an error
            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }
            // Check if the role is valid
            const role = loginUserDto.role;
            // If the role is invalid, throw an error
            if (role != user.role) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Role not valid'
                });
            }
            // Return the user data and a new token
            const { password, favoriteMovie, ...result } = user;
            return {
                user: result,
                token: await this.signJWT({ email: user.email, id: user.id })
            };

        } catch (e) {
            // If something goes wrong, throw an error
            throw new RpcException({
                status: 400,
                message: e.message
            })
        }
    }

    async resetPassword(email: string, password: string, favoriteMovie: string) {
        return await this.userClient.send({ cmd: 'reset_password' }, { email, password, favoriteMovie });
    }
}
