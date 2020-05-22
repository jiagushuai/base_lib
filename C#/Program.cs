using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace demo
{
    using System.Runtime.InteropServices;

    class Program
    {
        [DllImport("hello", EntryPoint = "test1", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr test1(int length, string param);

        [DllImport("hello", EntryPoint = "test2", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int test2(IntPtr result);
        static void Main(string[] args)
        {
            string param = "小路人";
            int length = 6;
            IntPtr ipName = test1(length,param);
            string ResName = Marshal.PtrToStringAnsi(ipName);
            Console.WriteLine("test1\t" + ResName);
           
            IntPtr ipName2 = Marshal.AllocHGlobal(256); ;
            int rv = test2(ipName2);
            ResName = Marshal.PtrToStringAnsi(ipName2);
            Console.WriteLine("test2\t" + ResName);

            Console.ReadKey();
        }

    }
}
