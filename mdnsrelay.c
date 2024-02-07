
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef __linux__
#define MSG_CONFIRM 0
#endif

#define MAX_PACKET_LENGTH 65535  // Maximum UDP packet size.

#define USE_NATIVE_DNS

typedef struct {
  uint16_t identifier_be;
  uint16_t flags_be;
  uint16_t questionCount_be;
  uint16_t answerCount_be;
  uint16_t authorityCount_be;
  uint16_t additionalCount_be;
  uint8_t data[MAX_PACKET_LENGTH - 8];
} dnspacket_header_t;

uint8_t *appendRequest(uint8_t *base, uint8_t *inputBuffer, uint8_t *outputBuffer, int *outputLength);

in_addr_t resolveMulticastDNS(char *hostname);


int main(int argc, char *argv[]) {
  int sock;
  if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Could not open listen socket");
    return(1);
  }

  struct sockaddr_in serverAddress;

  bzero(&serverAddress, sizeof(serverAddress));
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_addr.s_addr = INADDR_ANY;
  serverAddress.sin_port = htons(53);

  if (bind(sock, (const struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
    perror("Could not bind listen socket");
    return(1);
  }

  while (true) {
    struct sockaddr_in clientAddress;
    socklen_t addressLength = sizeof(clientAddress);

    bzero(&clientAddress, addressLength);

    uint8_t receivedData[MAX_PACKET_LENGTH];
    int receivedLength = recvfrom(sock, (void *)receivedData, MAX_PACKET_LENGTH,
                MSG_WAITALL, (struct sockaddr *)&clientAddress,
                &addressLength);
    dnspacket_header_t *packetHeader = (dnspacket_header_t *)&receivedData[0];

    fprintf(stderr, "First ten: %d %d %d %d %d %d %d %d %d %d\n",
        receivedData[0], receivedData[1], receivedData[2], receivedData[3], receivedData[4],
        receivedData[5], receivedData[6], receivedData[7], receivedData[8], receivedData[9]);
    fprintf(stderr, "First ten: %d %d %d %d %d %d %d %d %d %d\n",
        receivedData[10], receivedData[11], receivedData[12], receivedData[13], receivedData[14],
        receivedData[15], receivedData[16], receivedData[17], receivedData[18], receivedData[19]);

    fprintf(stderr, "Response:");
    for (int j = 0; j < receivedLength; j++) {
      fprintf(stderr, " 0x%02x", receivedData[j]);
    }
    fprintf(stderr, "\n");

    uint16_t identifier = ntohs(packetHeader->identifier_be);
    uint16_t flags = ntohs(packetHeader->flags_be);
    uint16_t questionCount = ntohs(packetHeader->questionCount_be);
    uint16_t answerCount = ntohs(packetHeader->answerCount_be);
    uint16_t authorityCount = ntohs(packetHeader->authorityCount_be);
    uint16_t additionalCount = ntohs(packetHeader->additionalCount_be);

    uint8_t responseBuffer[MAX_PACKET_LENGTH];

    fprintf(stderr, "Length: %d\n", receivedLength);
    fprintf(stderr, "Flags: %d\n", flags);
    fprintf(stderr, "Identifier: %d\n", identifier);
    fprintf(stderr, "Question count: %d\n", questionCount);
    fprintf(stderr, "Answer count: %d\n", answerCount);
    fprintf(stderr, "Authority count: %d\n", authorityCount);
    fprintf(stderr, "Additional count: %d\n", additionalCount);

    dnspacket_header_t *responsePacket = (dnspacket_header_t *)responseBuffer;
    uint8_t *outputPosition = responsePacket->data;

    uint64_t lengthToCopy = receivedLength - 12;
    memcpy(outputPosition, packetHeader->data, lengthToCopy);

    outputPosition += lengthToCopy;

    // This is counterintuitive, but we need to know the offsets.
    uint8_t *dataPosition = packetHeader->data;

    int responseCount = 0;
    for (int i = 0 ; i < questionCount; i++) {
      int outputLength = 0;
      fprintf(stderr, "Output position 0x%p", outputPosition);
      dataPosition = appendRequest(receivedData, dataPosition, outputPosition, &outputLength);
      outputPosition += outputLength;
      if (outputLength > 0) {
        responseCount++;
      }
    }

    // If recursion requested, set flag to say it is allowed.  Also, set the
    // response flags.  Note that the official DNS docs list the bits backwards.
    flags = flags | ((flags & 0x100) ? 0x80 : 0) | 0x8000;

    responsePacket->identifier_be = packetHeader->identifier_be;
    responsePacket->flags_be = htons(flags);
    responsePacket->questionCount_be = htons(questionCount);
    responsePacket->answerCount_be = htons(responseCount);
    responsePacket->authorityCount_be = 0;
    responsePacket->additionalCount_be = 0;

    fprintf(stderr, "Response:");
    for (int j = 0; j < (outputPosition - responseBuffer); j++) {
      fprintf(stderr, " 0x%02x", responseBuffer[j]);
    }
    fprintf(stderr, "\n");

    sendto(sock, (void *)responseBuffer, (outputPosition - responseBuffer),
        MSG_CONFIRM, (const struct sockaddr *)&clientAddress,
            addressLength);
  }
  return 0;
}

uint8_t *appendRequest(uint8_t *base, uint8_t *inputBuffer, uint8_t *outputBuffer, int *outputLength) {
  uint8_t length = *inputBuffer;
  uint8_t *originalOutputBuffer = outputBuffer;

  // Each chunk of the name is preceded by a length byte.  We only care about the
  // first part, so just copy the first [length] bytes.

  char *query = malloc(length + 1);
  strncpy(query, (const char *)(inputBuffer + 1), length);
  query[length] = '\0';

  uint8_t *pos = inputBuffer + length + 1;
  uint8_t ignored_chunk_length = 255;
  while (ignored_chunk_length > 0) {
    ignored_chunk_length = *pos;
    pos += ignored_chunk_length + 1;
  }
  uint16_t *type_be = (uint16_t *)pos;
  uint16_t *class_be = (uint16_t *)(pos + 2);
  uint16_t type = ntohs(*type_be);
  uint16_t class = ntohs(*class_be);

  pos += 4;

  fprintf(stderr, "Got query for %s (type = %d class = %d).\n", query, type, class);

  if (type != 1 || class != 1) {
    *outputLength = 0;
    free(query);
    return pos;
  }

  char *mDNSQuery = NULL;
  asprintf(&mDNSQuery, "%s.local.", query);
  in_addr_t address = resolveMulticastDNS(mDNSQuery);

  if (address == 0) {
    // Resolution failed.  Bail.
    *outputLength = 0;
    free(query);
    free(mDNSQuery);
    return pos;
  }

fprintf(stderr, "Address is 0x%08x\n", address);

  // The original query is at inputBuffer, relative to base.
  uint16_t offset = inputBuffer - base;
  offset |= 0xc000;  // Set the two high bits.

fprintf(stderr, "Offset: 0x%p\n", base);
fprintf(stderr, "Offset: 0x%p\n", inputBuffer);
fprintf(stderr, "Offset: 0x%04x\n", offset);

  uint16_t *offsetRef = (uint16_t *)outputBuffer;
  *offsetRef = htons(offset);

  outputBuffer += 2;

  // Type 0x0001.
  *outputBuffer = 0; outputBuffer++;
  *outputBuffer = 1; outputBuffer++;

  // Class 0x0001.
  *outputBuffer = 0; outputBuffer++;
  *outputBuffer = 1; outputBuffer++;

  // 10 second TTL.
  *outputBuffer = 0; outputBuffer++;
  *outputBuffer = 0; outputBuffer++;
  *outputBuffer = 0; outputBuffer++;
  *outputBuffer = 10; outputBuffer++;

  // Data length (0x0004)
  *outputBuffer = 0; outputBuffer++;
  *outputBuffer = 4; outputBuffer++;

  uint32_t *valueRef = (uint32_t *)outputBuffer;
  *valueRef = address;

// *outputBuffer = 127; outputBuffer++;
// *outputBuffer = 0; outputBuffer++;
// *outputBuffer = 0; outputBuffer++;
// *outputBuffer = 1; outputBuffer++;

  outputBuffer += 4;

  // The total length is the back-reference plus 10 bytes for the length
  // and TTL values above plus four bytes for the actual values.
  *outputLength = outputBuffer - originalOutputBuffer;

  free(query);
  free(mDNSQuery);
  return pos;
}

#ifdef USE_NATIVE_DNS

in_addr_t resolveMulticastDNS(char *hostname) {
  in_addr_t address = 0;
  struct addrinfo *allResults;
  if (getaddrinfo(hostname, NULL, NULL, &allResults) != 0) {
    return address;
  }

  for (struct addrinfo *result = allResults; result != NULL; result = result->ai_next) {
    // Ignore IPv6 completely for now.
    if (result->ai_family == AF_INET) {
      struct sockaddr_in *sa = (struct sockaddr_in *)(result->ai_addr);
      address = sa->sin_addr.s_addr;
    }
  }

  freeaddrinfo(allResults);
  return address;
}

#else

in_addr_t resolveMulticastDNS(char *hostname) {
  struct in_addr addr;
  if (inet_aton("127.0.0.1", &addr)) {
    return addr.s_addr;
  }
  return 0;
}

#endif
