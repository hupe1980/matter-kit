/* An nRF52840: 1 MB of flash and 256 KB of RAM — the part rs-matter publishes its own numbers
   for, so that the two can be compared at all. The whole of both is given to the image here;
   a real product loses the SoftDevice's share of flash and the radio stack's share of RAM,
   which is the point of measuring what is left over. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
