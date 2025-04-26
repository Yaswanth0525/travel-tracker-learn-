import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LogniDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
    constructor(private prisma : PrismaService,private jwtService : JwtService) {}
    //handle user registration
    async register(registerDto:RegisterDto) {
        //check if user already exists
        //if not, create a new user
        //remove password from return the user object
        const {email,password} = registerDto;
        const existingUser = await this.prisma.user.findUnique({
            where: {
                email,
            },
        })
        if (existingUser) {
            throw new ConflictException('User already exists')
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newlyCreatedUser = await this.prisma.user.create({
            data:{
                email,
                password: hashedPassword,
            }
        })
        const {password: _, ...rest} = newlyCreatedUser;
        return rest;
    }
    //handle user login
    async login(loginDto : LogniDto){
        const {email,password}= loginDto;
        const user = await this.prisma.user.findUnique({
            where:{
                email,
            },
        })
        if (!user) {
            throw new UnauthorizedException('Invalid credentials')
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password!')
        }
        const token =this.jwtService.sign({userId : user.id})
        const {password:_, ...rest} = user;
        return {...rest, token};

    }
}
