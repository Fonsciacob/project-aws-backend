import { Body, Controller, Get, Param, Post, Res } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('/signin')
  auth(@Res() response, @Body() credentials) {
    return this.appService.authenticated(credentials, response);
  }

  @Post('/newPasswordReq')
  newPasswordReq(@Res() response, @Body() credentials) {
    return this.appService.newPasswordReq(credentials, response);
  }

  @Post('/verify')
  verifyMFA(@Body() code) {
    return this.appService.setupMFA(code);
  }

  @Post('/topt')
  toptReq(@Body() code) {
    return this.appService.totpReq(code);
  }
}
