import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { passportJwtSecret } from 'jwks-rsa';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    const supabaseUrl = configService.get<string>('SUPABASE_URL')?.trim();
    const anonKey = configService.get<string>('SUPABASE_ANON_KEY')?.trim();
    const jwksUri = `${supabaseUrl}/auth/v1/.well-known/jwks.json`;
    console.log('JwtStrategy - JWKS URI:', jwksUri);

    const secretProvider = passportJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: jwksUri,
      requestHeaders: {
        apikey: anonKey || '',
      },
      handleSigningKeyError: (err, cb) => {
        if (err)
          console.error('JwtStrategy - JWKS Key Retrieval Error:', err.message);
        return cb(err);
      },
    });

    /* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: (
        req: unknown,
        rawJwtToken: string,
        done: (err: Error | null, secret?: string | Buffer) => void,
      ) => {
        console.log('JwtStrategy - Providing secret for token');
        const provider = secretProvider as (
          req: any,
          token: string,
          cb: (err: Error | null, secret?: string | Buffer) => void,
        ) => void;
        provider(req, rawJwtToken, (err, secret) => {
          if (err) {
            console.error('JwtStrategy - Provider Error:', err.message);
          }
          done(err, secret);
        });
      },
      algorithms: ['ES256'],
      audience: 'authenticated',
      issuer: `${supabaseUrl}/auth/v1`,
    });
    /* eslint-enable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
    console.log('JwtStrategy - Initialized with JWKS');
  }

  validate(payload: { sub: string; email: string }) {
    console.log('JwtStrategy - Validating payload:', JSON.stringify(payload));
    return { userId: payload.sub, email: payload.email };
  }
}
