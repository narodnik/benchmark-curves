// Based on https://gist.github.com/CodesInChaos/ef914909941ce7caf514
// Uses libsodium library
// Not storing array, simply printing out

void cached_to_precomp(ge_precomp* preComp, ge_cached* cached)
{
    fe inverse;
    fe_invert(inverse, cached->Z);
    fe_mul(preComp->yminusx, cached->YminusX, inverse);
    fe_mul(preComp->yplusx, cached->YplusX, inverse);
    fe_mul(preComp->xy2d, cached->T2d, inverse);
}

void compute_row( ge_cached* b)
{
    ge_precomp result;
    ge_p3 p3;
    ge_p3_0(&p3);
    
    int j;
    for (  j = 0; j < 8; j++)
    {
        ge_p1p1 p1p1;
        ge_cached cached;

        ge_add(&p1p1, & p3, b);
        ge_p1p1_to_p3(& p3, & p1p1);
        ge_p3_to_cached(& cached, & p3);

        cached_to_precomp(&result, &cached);
         // TODO WRITE TO FLASH  
        int ap;
        printf("###\n");
        for(ap = 0; ap < 10; ap++)
        {
            printf("%d, ", result.yplusx[ap]);
        }
        printf("\n");
        for(ap = 0; ap < 10; ap++)
        {
            printf("%d, ", result.yminusx[ap]);
        }        
        printf("\n");
        for(ap = 0; ap < 10; ap++)
        {
            printf("%d, ", result.xy2d[ap]);
        }
        printf("\n");
    }
}

void compute_lookup_table(ge_cached* b)
{
    ge_p3 p3;
    ge_p2 p2;
    ge_p1p1 p1p1;
    ge_cached cached;

    ge_p3_0(&p3);
    ge_add(&p1p1, &p3, b);
    ge_p1p1_to_p3(&p3, &p1p1);

    int i, k;
    for ( i = 0; i < 32; i++)
    {
        printf("i = %d\n", i);
        ge_p3_to_cached(&cached, &p3);
        
        compute_row(&cached);
        
        ge_p3_to_p2(&p2,  &p3);
        
        // Calculate next base point
        
        for ( k = 0; k < 7; k++)
        {
            ge_p2_dbl( &p1p1,  &p2);
            ge_p1p1_to_p2( &p2,  &p1p1);
            printf("k = %d\n", k);
        }
        ge_p2_dbl(& p1p1, & p2);
        ge_p1p1_to_p3(& p3, & p1p1);
    }
}

void LOOKT_write_lookup_table_to_flash(void)
{    
    // First Base point, B0
    fe ypx =  {25967493,-14356035,29566456,3660896,-12694345,4014787,27544626,-11754271,-6079156,2047605};
    fe ymx =  {-12545711,934262,-2722910,3049990,-727428,9406986,12720692,5043384,19500929,-15469378};
    fe T2d =  {-8738181,4489570,9688441,-14785194,10184609,-12363380,29287919,11864899,-24514362,-4438546};
    fe Z; fe_1(Z);
    
    ge_cached Bi0;
    
    int p;
    for(p = 0; p < 10; p++)
    {
        Bi0.YplusX[p] = ypx[p];
        Bi0.YminusX[p] = ymx[p];
        Bi0.T2d[p] = T2d[p];
        Bi0.Z[p] = Z[p];
    }
    
    compute_lookup_table(&Bi0);      
}
