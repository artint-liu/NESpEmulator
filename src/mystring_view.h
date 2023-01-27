#ifndef _MY_STRING_VIEW_H_
#define _MY_STRING_VIEW_H_

struct MyStringView
{
    const char* m_str;

    MyStringView(const char* str) : m_str(str) {}
    operator const char* () const
    {
        return m_str;
    }
};

#endif // _MY_STRING_VIEW_H_