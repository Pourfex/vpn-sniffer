import fs from 'fs';
import csv from 'csv-parser';
import {createObjectCsvWriter} from 'csv-writer';
import {AsyncSubject, from, Observable} from "rxjs";
import {
    buffer, filter, finalize,
    groupBy,
    map,
    mergeAll,
    mergeMap, scan, skip,
    skipWhile,
    tap, toArray
} from "rxjs/internal/operators";
import _ from 'lodash';
import * as dns from "dns";
import memoizee from "memoizee";

const DEBOUNCE_TIME_MILLISECONDS = 1000;

const reverseLookup = (ip: string): Observable<string[]> => {
    const subject = new AsyncSubject<string[]>();
    dns.reverse(ip, (err, domains) => {
        let ips = [ip];
        if (err == null) {
            ips = [...ips, ...domains];
        }
        subject.next(ips);
        subject.complete();
    });
    return subject.asObservable()
};

const memoizedReverseLookup = memoizee(reverseLookup);

interface Packet {
    type: 'udp' | 'tcp';
    size: number;
    timestamp: number;
    ip: string;
}

interface EnrichedPacket {
    previous: Packet;
    current: Packet;
}

interface ProcessedPacket {
    type: 'udp' | 'tcp';
    size: number;
    start: number;
    end: number;
    ips: string;
    numPackets: number;
}

const lines: Packet[] = [];

const interpret = () => {

    const enrichLines = (lines$: Observable<Packet>) =>
        lines$
            .pipe(
                scan(((acc, current) => ({
                    previous: acc.current,
                    current
                })), {} as any),
                skip(1)
            );

    const debounceLines = (enrichedLines$: Observable<EnrichedPacket>) => {
        const bufferToggle$ = enrichedLines$
            .pipe(
                skipWhile(line => line.current.timestamp < (line.previous.timestamp + DEBOUNCE_TIME_MILLISECONDS)),
            );
        return enrichedLines$
            .pipe(
                buffer(bufferToggle$),
                filter(enrichedLines => enrichedLines.length !== 0),
                map(enrichedLines => enrichedLines.map(enrichedLine => enrichedLine.previous))
            );
    };

    const processPackets = (packets: Packet[]): Observable<ProcessedPacket> => {
        const {type, ip} = packets[0];
        const start = _.minBy(packets, packet => packet.timestamp).timestamp;
        const end = _.maxBy(packets, packet => packet.timestamp).timestamp;
        const size = _.sumBy(packets, packet => packet.size);
        return memoizedReverseLookup(ip)
            .pipe(
                map(ips => ips.join('|')),
                map(ips => ({
                    type,
                    ips,
                    start,
                    end,
                    size,
                    numPackets: packets.length
                }))
            )
    };

    const csvWriter = createObjectCsvWriter({
        path: 'result.csv',
        header: [
            {id: 'type', title: 'TYPE'},
            {id: 'numPackets', title: 'NUM_PACKETS'},
            {id: 'ips', title: 'IPS'},
            {id: 'start', title: 'START'},
            {id: 'end', title: 'END'},
            {id: 'size', title: 'SIZE'}
        ]
    });

    from(lines)
        .pipe(
            groupBy(line => line.type + '-' + line.ip),
            map(enrichLines),
            map(debounceLines),
            mergeAll(),
            mergeMap(processPackets),
            toArray(),
            tap((processedPackets: ProcessedPacket[]) => csvWriter.writeRecords(processedPackets)),
            finalize(() => console.log('Saved CSV!'))
        )
        .subscribe()

};


fs.createReadStream('packets.txt')
    .pipe(csv())
    .on('data', data => {
        lines.push({
            type: data.type,
            size: Number.parseInt(data.size),
            timestamp: Number.parseInt(data.timestamp),
            ip: data.ip
        });
    })
    .on('end', () => interpret());
