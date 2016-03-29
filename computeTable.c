
/*
 * compute table T0 = X0 . H
 * the value of first byte of X0 is between [0, 255], other bytes are all 0
 * 
 */
static void computeTable (uint8_t table[][16]) {

	// zh is the higher 64-bit, zl is the lower 64-bit.
	uint64_t zh = 0, zl = 0;
	// vh is the higher 64-bit, vl is the lower 64-bit.
	uint64_t vh = ((uint64_t)H[0]<<56) + ((uint64_t)H[1]<<48) + ((uint64_t)H[2]<<40) + ((uint64_t)H[3]<<32) +
			((uint64_t)H[4]<<24) + ((uint64_t)H[5]<<16) + ((uint64_t)H[6]<<8) + ((uint64_t)H[7]);
	uint64_t vl = ((uint64_t)H[8]<<56) + ((uint64_t)H[9]<<48) + ((uint64_t)H[10]<<40) + ((uint64_t)H[11]<<32) +
			((uint64_t)H[12]<<24) + ((uint64_t)H[13]<<16) + ((uint64_t)H[14]<<8) + ((uint64_t)H[15]);

	uint8_t temph;
	uint8_t i = 0, j = 0;
	for ( i = 0; i < 256; i++ ) {
		temph = i;
		for ( j = 0; j < 8; j++ ) {
			if ( 0x80 & temph ) {
				zh ^= vh;
				zl ^= vl;
			}
			if ( vl & 0x1 ) {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
				vh ^= FIELD_CONST;
			} else {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
			}
			temph = temph << 1;
		}
		// get result
		for ( j = 1; j <= BLOCK_CIPHER_BLOCK_SIZE/2; j++ ) {
			table[i][BLOCK_CIPHER_BLOCK_SIZE/2-i] = (uint8_t)zh;
			zh = zh >> 8;
			table[i][BLOCK_CIPHER_BLOCK_SIZE-i] = (uint8_t)zl;
			zl = zl >> 8;
		}
	}
}

/**
 * compute T1, T2, ... , and T15
 * T1 = T0 . P^8
 * T2 = T1 . P^8 = T0 . P^16
 * T3 = T2 . P^8 = T0 . P^24
 * ...
 * T15 = T14 . P^8 = T0 . P^120
 *
 */
static void otherT() {
	int i = 0, j = 0;
	uint64_t vh, vl;
	uint64_t zh, zl;
	for ( i = 0; i < 256; i++ ) {
		vh = ((uint64_t)T[0][i][0]<<56) + ((uint64_t)T[0][i][1]<<48) + ((uint64_t)T[0][i][2]<<40) + ((uint64_t)T[0][i][3]<<32) +
			((uint64_t)T[0][i][4]<<24) + ((uint64_t)T[0][i][5]<<16) + ((uint64_t)T[0][i][6]<<8) + ((uint64_t)T[0][i][7]);
		vl = ((uint64_t)T[0][i][8]<<56) + ((uint64_t)T[0][i][9]<<48) + ((uint64_t)T[0][i][10]<<40) + ((uint64_t)T[0][i][11]<<32) +
			((uint64_t)T[0][i][12]<<24) + ((uint64_t)T[0][i][13]<<16) + ((uint64_t)T[0][i][14]<<8) + ((uint64_t)T[0][i][15]);
		zh = zl = 0;
		for ( j = 0; j <= 120; j++ ) {
			if ( j > 0 && 0 == j % 8 ) {
				zh ^= vh;
				zl ^= vl;
				for ( j = 1; j <= BLOCK_CIPHER_BLOCK_SIZE/2; j++ ) {
					T[j/8][i][BLOCK_CIPHER_BLOCK_SIZE/2-i] = (uint8_t)zh;
					zh = zh >> 8;
					T[j/8][i][BLOCK_CIPHER_BLOCK_SIZE-i] = (uint8_t)zl;
					zl = zl >> 8;
				}
			}
			if ( vl & 0x1 ) {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
				vh ^= FIELD_CONST;
			} else {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
			}
		}
	}
}






