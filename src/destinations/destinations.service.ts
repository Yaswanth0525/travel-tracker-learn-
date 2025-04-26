import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateDestinationDto } from './dto/create-destination.dto';

@Injectable()
export class DestinationsService {
    constructor(private prisma : PrismaService) {}
    async create(userId : number, createDestinationDto: CreateDestinationDto){
        return this.prisma.destination.create({
            data: {
                ...createDestinationDto,
                travelDate : new Date(createDestinationDto.travelDate).toISOString(),
                userId: userId
            }
        })
    }
}
