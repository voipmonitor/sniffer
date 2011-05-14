void slinear_saturated_add(short *input, short *value) {
	int res;

        res = (int) *input + *value;
        if (res > 32767)
                *input = 32767;
        else if (res < -32767)
                *input = -32767;
        else
                *input = (short) res;
}

