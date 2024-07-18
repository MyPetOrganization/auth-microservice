import { Inject, Injectable } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import * as dotenv from 'dotenv';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcryptjs';
import { firstValueFrom } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

dotenv.config();

@Injectable()
export class AuthService {
    constructor(
        @Inject(process.env.USER_SERVICE) private readonly userClient: ClientProxy,
        private readonly jwtService: JwtService
    ) { }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async verifyToken(token: string) {
        try {
            const { sub, iat, exp, ...user} = await this.jwtService.verify(token);

            return {
                user: user,
                token: await this.signJWT(user)
            }
        } catch (e) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            });
        }
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        const email = registerUserDto.email;

        try {
            const user = await firstValueFrom(this.userClient.send({ cmd: 'get_user_by_email' }, {email}));
            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }
            
            const payload: any = {
                createUserDto: registerUserDto,
                image: null,
            };
            return this.userClient.send({ cmd: 'create_user' }, payload);
        } catch (e) {
            throw new RpcException({
                status: 400,
                message: e.message
            })
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const email = loginUserDto.email;

        try {
            const user = await firstValueFrom(this.userClient.send({ cmd: 'get_user_by_email' }, {email}));

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const isPasswordValid = await bcrypt.compareSync(loginUserDto.password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const { password, ...result } = user;
            return {
                user: result,
                token: await this.signJWT({ email: user.email, id: user.id })
            };

        } catch (e) {
            throw new RpcException({
                status: 400,
                message: e.message
            })
        }
    }
}
