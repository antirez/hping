#ifndef __APD_UTILS_H
#define __APD_UTILS_H

int ars_d_firstfield_off(char *packet, char *layer, char *field,
		int *field_start, int *value_start, int *value_end);
int ars_d_field_off(char *packet, char *layer, char *field, int skip,
		int *field_start, int *value_start, int *value_end);
char *ars_d_field_get(char *packet, char *layer, char *field, int skip);

#endif
