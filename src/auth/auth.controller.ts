import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
  @UseGuards(JwtAuthGuard)
  @Get('test')
  getProfile(@Request() req: ExpressRequest) {
    const user = (req as unknown as { user: { userId: string; email: string } })
      .user;
    return {
      message: 'Autenticação bem-sucedida!',
      user,
    };
  }
}
