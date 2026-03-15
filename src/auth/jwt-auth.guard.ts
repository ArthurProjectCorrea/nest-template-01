import {
  Injectable,
  UnauthorizedException,
  ExecutionContext,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest<TUser = any>(
    err: unknown,
    user: TUser,
    info: unknown,
    context: ExecutionContext,
  ): TUser {
    if (err || !user) {
      const request = context.switchToHttp().getRequest<{
        headers: { authorization?: string };
      }>();
      const authHeader = request.headers?.authorization;
      const token = authHeader?.split(' ')[1];

      console.error('JwtAuthGuard - Authentication failed:');
      const infoMessage =
        info instanceof Error
          ? info.message
          : typeof info === 'object' && info !== null && 'message' in info
            ? (info as { message: string }).message
            : String(info);
      console.error('- Info:', infoMessage);

      if (token) {
        try {
          const parts = token.split('.');
          const headerB64 = parts[0];
          const payloadB64 = parts[1];
          if (headerB64 && payloadB64) {
            const headerBuffer = Buffer.from(headerB64, 'base64');
            const headerStr = headerBuffer.toString('utf-8');
            const header = JSON.parse(headerStr) as unknown;

            const payloadBuffer = Buffer.from(payloadB64, 'base64');
            const payloadStr = payloadBuffer.toString('utf-8');
            const payload = JSON.parse(payloadStr) as unknown;

            console.log(
              'JwtAuthGuard - Debug Token Header:',
              JSON.stringify(header),
            );
            console.log(
              'JwtAuthGuard - Debug Token Payload:',
              JSON.stringify(payload),
            );
          }
        } catch (e: unknown) {
          const error = e as Error;
          console.error(
            'JwtAuthGuard - Could not decode token:',
            error?.message,
          );
        }
      } else {
        console.warn('JwtAuthGuard - No token found in authorization header');
      }

      throw (
        (err as Error) || new UnauthorizedException('Falha na autenticação JWT')
      );
    }
    return user;
  }
}
