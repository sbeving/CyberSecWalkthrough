# Impossimaze

\


```
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // ebx
  int i; // ebx
  unsigned int v5; // r12d
  int v6; // ebx
  unsigned int v7; // ebp
  int v8; // eax
  int v9; // r14d
  int *v10; // rbp
  int j; // ebx
  int v12; // edx
  int v14; // [rsp+Ch] [rbp-6Ch]
  int v15; // [rsp+10h] [rbp-68h]
  int v16; // [rsp+14h] [rbp-64h]
  char v17[24]; // [rsp+20h] [rbp-58h] BYREF
  unsigned __int64 v18; // [rsp+38h] [rbp-40h]

  v18 = __readfsqword(0x28u);
  initscr();
  cbreak();
  noecho();
  curs_set(0);
  keypad(stdscr, 1);
  v3 = getmaxy(stdscr);
  v15 = getmaxx(stdscr) / 2;
  v16 = v3 / 2;
  for ( i = 0; i != 113; i = wgetch(stdscr) )
  {
    v9 = getmaxy(stdscr);
    v14 = getmaxx(stdscr);
    if ( i == 260 )
    {
      v15 -= v15 > 1;
    }
    else if ( i > 260 )
    {
      v15 += i == 261;
    }
    else if ( i == 258 )
    {
      ++v16;
    }
    else if ( i == 259 )
    {
      v16 -= v16 > 1;
    }
    werase(stdscr);
    wattr_on(stdscr, 0x100000uLL, 0LL);
    wborder(stdscr, 0LL, 0LL, 0LL, 0LL, 0LL, 0LL, 0LL, 0LL);
    if ( v14 > 2 )
    {
      v5 = 1;
      do
      {
        v7 = 1;
        if ( v9 > 2 )
        {
          do
          {
            v8 = sub_1249(v5, v7);
            if ( v8 > 60 )
            {
              v6 = (unsigned int)(v8 - 61) < 0x78 ? 32 : 86;
            }
            else
            {
              LOBYTE(v6) = 65;
              if ( v8 <= 30 )
                v6 = (unsigned int)v8 < 0x1F ? -37 : 86;
            }
            if ( wmove(stdscr, v7, v5) != -1 )
              waddch(stdscr, (unsigned int)(char)v6);
            ++v7;
          }
          while ( v7 != v9 - 1 );
        }
        ++v5;
      }
      while ( v14 - 1 != v5 );
    }
    wattr_off(stdscr, 0x100000uLL, 0LL);
    wattr_on(stdscr, 0x200000uLL, 0LL);
    if ( wmove(stdscr, v16, v15) != -1 )
      waddch(stdscr, 0x58uLL);
    wattr_off(stdscr, 0x200000uLL, 0LL);
    snprintf(v17, 0x10uLL, "%d:%d", v9, v14);
    if ( wmove(stdscr, 0, 0) != -1 )
      waddnstr(stdscr, v17, -1);
    if ( v9 == 13 && v14 == 37 )
    {
      wattr_on(stdscr, 0x80000uLL, 0LL);
      wattr_on(stdscr, 0x200000uLL, 0LL);
      v10 = (int *)&unk_40C0;
      for ( j = 6; j != 30; ++j )
      {
        v12 = j;
        if ( wmove(stdscr, 6, v12) != -1 )
          waddch(stdscr, byte_4120[*v10]);
        ++v10;
      }
      wattr_off(stdscr, 0x200000uLL, 0LL);
      wattr_off(stdscr, 0x80000uLL, 0LL);
    }
  }
  endwin();
  return 0LL;
}

```



## Resize window 2 37x13 to get the flag

\


<figure><img src="../../../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>
