import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Merchant, MerchantStatus } from '../../merchants/entities/merchant.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    @InjectRepository(Merchant)
    private readonly merchantsRepo: Repository<Merchant>,
  ) {
    const secret = config.get<string>('JWT_SECRET');
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is not set. Refusing to start with an insecure fallback.');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: secret,
    });
  }

  async validate(payload: { sub: string; email: string; role: string }) {
    const merchant = await this.merchantsRepo.findOne({ where: { id: payload.sub } });
    if (!merchant) throw new UnauthorizedException('Merchant not found');

    // Verify merchant is active (issue #87: prevent suspended merchants from using tokens)
    if (merchant.status !== MerchantStatus.ACTIVE) {
      throw new UnauthorizedException(`Merchant account is ${merchant.status} and cannot access the API`);
    }

    return { merchantId: merchant.id, email: merchant.email, role: merchant.role };
  }
}
