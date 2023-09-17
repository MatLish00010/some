import { Injectable } from '@nestjs/common';

import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  login() {
    return {
      message: 'Test mess_1',
    };
  }

  signUp(dto: AuthDto) {
    console.log('serviceDTO:', dto);
    return {
      message: 'Test mess_2',
    };
  }
}
