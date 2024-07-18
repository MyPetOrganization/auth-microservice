import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import * as dotenv from 'dotenv';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

dotenv.config();

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule,
    {
      transport: Transport.NATS,
      options: {
        servers: process.env.NATS_SERVER,
      },
    }
  );

  await app.listen();

  Logger.log(`Auth microservice is running on: ${process.env.PORT}`, 'Bootstrap');
}
bootstrap();
