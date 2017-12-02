using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Forms;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
namespace GrammarAnalyser
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        String InputFileName = "";
        String OutputFileName = "";
        String outputdir = "";
        GAparser parser = new GAparser();
        public MainWindow()
        {
            InitializeComponent();
        }
        
        class GAparser
        {
            class myitem
            {
                public String content = "";
                public String attribute = "";  //also be used as VT when finding firstVT and lastVT
                myitem()
                {

                }
                public myitem(String content, String attribute)
                {
                    this.content = content;
                    this.attribute = attribute;
                }
            }
            List<List<myitem>> Rules = new List<List<myitem>>();  //Remove ::=
            Dictionary<String, HashSet<String>> FIRSTVT = new Dictionary<string, HashSet<string>>(), LASTVT = new Dictionary<string, HashSet<string>>();
            List<myitem> stack = new List<myitem>();
            Dictionary<string, string> SymbolTable = new Dictionary<string, string>();
            List<Tuple<List<myitem>, int>> History = new List<Tuple<List<myitem>, int>>();
            String sourcetext="";
            Dictionary<Tuple<String, String>, int> Matrix = new Dictionary<Tuple<string, string>, int>();
            //0 - <,1 - >,2 - =,not exist-unknown
            String[] buf = null;
            String[] sentence = null;
            public string error_msg = "";
            public int error_status = 0;
            //List<List<Boolean>> stringmask = new List<List<Boolean>>();
            private void firstvt_insert(String VN,String VT)
            {
                if (!FIRSTVT.ContainsKey(VN))
                {
                    FIRSTVT.Add(VN, new HashSet<string>());
                }
                FIRSTVT[VN].Add(VT);
                stack.Add(new myitem(VN, VT));
            }
            private void lastvt_insert(String VN, String VT)
            {
                if (!LASTVT.ContainsKey(VN))
                {
                    LASTVT.Add(VN, new HashSet<string>());
                }
                LASTVT[VN].Add(VT);
                stack.Add(new myitem(VN, VT));
            }
            private void segmentSource()
            {
                buf = sourcetext.Split('\n');
            }
            public List<List<String>> parse(String text)
            {
                sourcetext = text.ToString();
                segmentSource();
                find_all_vn_and_build_sym_table(); //also build rules
                clean_work();
                return null;
            }
            private List<int> AllIndexesOf(string str, string value)
            {
                if (String.IsNullOrEmpty(value))
                    throw new ArgumentException("the string to find may not be empty", "value");
                List<int> indexes = new List<int>();
                for (int index = 0; ; index += value.Length)
                {
                    index = str.IndexOf(value, index);
                    if (index == -1)
                        return indexes;
                    indexes.Add(index);
                }
            }
            private void find_all_vn_and_build_sym_table()
            {
                //int line = 0,col = 0;
                foreach(String e in buf)
                {
                    List<myitem> now = new List<myitem>();
                    //int position = e.IndexOf("::=");
                    //string s = e.Substring(0, position);
                    String[] strbuf = e.Split(' ');
                    string s = strbuf[0];
                    SymbolTable[s] = "VN";
                    now.Add(new myitem(s,"VN"));
                    Rules.Add(now);
                    //List<Boolean> mask = new List<Boolean>();
                    //int length = e.Length;
                    //for (int i = 0; i < position+3; i++)
                      //  mask.Add(false);
                    //for (int i = position + 3; i < length; i++)
                     //   mask.Add(true);
                    //stringmask.Add(mask);
                }
                int count = 0;
           
                foreach (String s in buf)
                {
        
                    string[] strbuf = s.Split(' ');
                    List<myitem> now = new List<myitem>();
                    now.Add(new myitem(strbuf[0],"VN"));
                    int length = strbuf.Length;
                    for (int i =2;i<length;i++)
                    {
                        if (SymbolTable.ContainsKey(strbuf[i]))
                        {
                            Rules[count].Add(new myitem(strbuf[i], SymbolTable[strbuf[i]]));
                        }
                        else
                        {
                            Rules[count].Add(new myitem(strbuf[i], "VT"));
                            SymbolTable[strbuf[i]] = "VT";
                        }
                    }
                    count++;
                }
            }  //also build rules
            private void find_first_vt()
            {
                foreach (var list in Rules)
                {
                    if (list.Count>=2)
                    {
                        if (list[1].attribute.Equals("VT"))
                        {
                            firstvt_insert(list[0].content, list[1].content);
                        }
                    }
                    if (list.Count>=3)
                    {
                        if (list[2].attribute.Equals("VT") && list[1].attribute.Equals("VN"))
                            firstvt_insert(list[0].content, list[2].content);
                    }
                }
                while (stack.Count>0)
                {
                    int stack_count = stack.Count;
                    myitem now = stack[stack_count - 1];
                    string V = now.content;
                    string b = now.attribute;
                    foreach (var list in Rules)
                    {
                        if (list.Count>=2)
                        {
                            if (list[1].content.Equals(V))
                            {
                                firstvt_insert(list[0].content, b);
                            }
                        }
                    }
                    stack.RemoveAt(stack_count - 1);

                }
            }
            private void find_last_vt()
            {
                foreach (var list in Rules)
                {
                    int list_count = list.Count;
                    if (list.Count >= 2)
                    {
                        if (list[list_count-1].attribute.Equals("VT"))
                        {
                            lastvt_insert(list[0].content, list[list_count-1].content);
                        }
                    }
                    if (list.Count >= 3)
                    {
                        if (list[list_count-2].attribute.Equals("VT") && list[list_count-1].attribute.Equals("VN"))
                            lastvt_insert(list[0].content, list[list_count-2].content);
                    }
                }
                while (stack.Count > 0)
                {
                    int stack_count = stack.Count;
                    myitem now = stack[stack_count - 1];
                    string V = now.content;
                    string b = now.attribute;
                    foreach (var list in Rules)
                    {
                        if (list.Count >= 2)
                        {
                            if (list[list.Count-1].content.Equals(V))
                            {
                                lastvt_insert(list[0].content, b);
                            }
                        }
                    }
                    stack.RemoveAt(stack_count - 1);

                }
            }
            private void build_matrix()
            {
                foreach (var list in Rules)
                {
                    if (list.Count>=3 && error_status == 0)
                    {
                        int length = list.Count;
                        for (int i=2;i<length;i++)
                        {
                            //
                            if (list[i].attribute.Equals("VN") && list[i-1].attribute.Equals("VT"))
                            {
                                foreach (var item in FIRSTVT[list[i].content])
                                {
                                    var now_item = new Tuple<String, String>(list[i - 1].content, item);
                                    if (Matrix.ContainsKey(now_item))
                                    {
                                        if (Matrix[now_item] == 0)
                                            continue;
                                        else
                                        {
                                            error_msg = "Not an OG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
                                            error_status = -1;
                                            break;
                                        }

                                    }
                                    else
                                    {
                                        Matrix.Add(now_item, 0);
                                    }
                                }
                            }
                            else if (list[i].attribute.Equals("VT") && list[i - 1].attribute.Equals("VN"))
                            {
                                foreach (var item in LASTVT[list[i-1].content])
                                {
                                    var now_item = new Tuple<String, String>(item, list[i].content);
                                    if (Matrix.ContainsKey(now_item))
                                    {
                                        if (Matrix[now_item] == 1)
                                            continue;
                                        else
                                        {
                                            error_msg = "Not an OG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
                                            error_status = -1;
                                            break;
                                        }

                                    }
                                    else
                                    {
                                        Matrix.Add(now_item, 1);
                                    }
                                }
                            }
                            else if (list[i].attribute.Equals("VT") && list[i-1].attribute.Equals("VT"))
                            {
                                var now_item = new Tuple<String, String>(list[i - 1].content, list[i].content);
                                if (Matrix.ContainsKey(now_item))
                                {
                                    if (Matrix[now_item] == 2)
                                        continue;
                                    else
                                    {
                                        error_msg = "Not an OG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
                                        error_status = -1;
                                        break;
                                    }
                                }
                                else
                                {
                                    Matrix.Add(now_item, 2);
                                }
                            }
                            if (i+1<length)
                            {
                                if (list[i-1].attribute.Equals("VT") && list[i].attribute.Equals("VN") && list[i+1].attribute.Equals("VT"))
                                {
                                    var now_item = new Tuple<String, String>(list[i - 1].content, list[i+1].content);
                                    if (Matrix.ContainsKey(now_item))
                                    {
                                        if (Matrix[now_item] == 2)
                                            continue;
                                        else
                                        {
                                            error_msg = "Not an OG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
                                            error_status = -1;
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        Matrix.Add(now_item, 2);
                                    }
                                }
                            }
                        }
                    }
                }
                foreach (var item in SymbolTable)
                {
                    if (item.Value.Equals("VT"))
                    {
                        Matrix.Add(new Tuple<string, string>("#",item.Value),0);
                        Matrix.Add(new Tuple<string, string>(item.Value,"#"), 1);
                    }
                }
                Matrix.Add(new Tuple<string, string>("#","#"),2);
            }
            private int search(List<myitem> stack_tmp,String symbol)
            { 
                int length = stack_tmp.Count;
                for (int i=length-1;i>=0;i--)
                {
                    if (stack_tmp[i].attribute.Equals("VN"))
                        continue;
                    var now_item = new Tuple<String, String>(stack_tmp[i].content, symbol);
                    if (!Matrix.ContainsKey(now_item))
                        return -1;
                    if (Matrix[now_item] == 0)
                        return i;
                }
                return -1;
            }
            private int search_vt(List<myitem> stack_tmp)
            {

                int count = stack_tmp.Count;
                for (int i =count-1;i>=0;i--)
                {
                    if (stack_tmp[i].attribute.Equals("VT"))
                        return i;
                }
                return -1;
            }
            private List<List<myitem>>getAllCandidate(List<myitem> pattern,List<myitem> source)
            {
                List<myitem> buf = new List<myitem>();
                List<List<myitem>> res = new List<List<myitem>>();
                int match_len = pattern.Count;
                HashSet<myitem> set = new HashSet<myitem>();
                foreach (var item in Rules)
                {
                    int length0 = item.Count;
                    if (length0 - 1 != match_len) continue;
                    bool flag = true;
                    for (int index=0;index<match_len;index++)
                    {
                         if (!(item[1+index].content.Equals(pattern[index].content) && item[1+index].attribute.Equals(pattern[index].attribute)))
                         {
                            flag = false;
                            break;
                        }
                    }
                    if (flag)
                    {
                        buf.Add(item[0]);
                        set.Add(item[0]);
                        var new_stack = new List<myitem>(source);
                        new_stack.Add(item[0]);
                        res.Add(new_stack);
                    }
                }
                int i = 0;
                while (i<buf.Count)
                {
                    foreach(var item in Rules)
                    {
                        if (set.Contains(item[0]))
                            continue;
                        if (item.Count != 2) continue;
                        else
                        if (item[1].content==buf[i].content && item[1].attribute==buf[i].attribute)
                        {
                            buf.Add(item[0]);
                            set.Add(item[0]);
                            var new_stack = new List<myitem>(source);
                            new_stack.Add(item[0]);
                            res.Add(new_stack);
                        }
                    }
                    i++;
                }
                return res;
            }
            private int work()
            {
                int count = History.Count();
                var last_status = History[count];
                int nowvt = search_vt(last_status.Item1);
                if (nowvt < 0) return -1;
                string nowsymbol = this.sentence[last_status.Item2];
                string stacksymbol = last_status.Item1[nowvt].content;
                if (!SymbolTable.ContainsKey(nowsymbol)) return -1;
                if (!SymbolTable[nowsymbol].Equals("VT")) return -1;
                var now_item = new Tuple<String, String>(stacksymbol, nowsymbol);
                if (!Matrix.ContainsKey(now_item)) return -1;
                if (Matrix[now_item]==0)
                {
                    var stack_tmp = new List<myitem>(last_status.Item1);
                    stack_tmp.Add(new myitem(nowsymbol, SymbolTable[nowsymbol]));
                    History.Add(new Tuple<List<myitem>, int>(stack_tmp, last_status.Item2 + 1));
                    int res = work();
                    if (res < 0)
                    {
                        int length = History.Count();
                        History.RemoveAt(length);
                    }
                    else return 0;
                }
                else
                {
                    int reduce_position = search(last_status.Item1,nowsymbol);
                    if (reduce_position < 0) return -1;
                    int length = last_status.Item1.Count;
                    List<myitem> pattern = new List<myitem>();
                    List<myitem> source = new List<myitem>();
                    for (int i = 0; i <= reduce_position; i++)
                        source.Add(last_status.Item1[i]);
                    for (int i=reduce_position+1;i<length;i++)
                    {
                        pattern.Add(last_status.Item1[i]);
                    }
                    List<List<myitem>> candidate_status = getAllCandidate(pattern,source);
                    for (int i=0;i<candidate_status.Count;i++)
                    {
                        History.Add(new Tuple<List<myitem>, int>(candidate_status[i], nowvt));
                        int res = work();
                        if (res < 0)
                        {
                            int tmp = History.Count;
                            History.RemoveAt(tmp);
                        }
                        else return 0;
                    }
                }
                return -1;
            }
            private int analysis(string sentence)
            {
                var stack_tmp = new List<myitem>();
                stack_tmp.Add(new myitem("#","VT"));
                History.Add(new Tuple<List<myitem>, int>(stack_tmp, 0));
                this.sentence = sentence.Split(' ');
                int res = work();
                return res;
            }
            private void clean_work()
            {
                Rules.Clear();
                FIRSTVT.Clear();
                LASTVT.Clear();
                stack.Clear();
                buf = null;
                sourcetext = "";
                SymbolTable.Clear();
                //stringmask.Clear();
                Matrix.Clear();
                error_msg = "";
                error_status = 0;
                History.Clear();
            }
        }
        private void InputButton_Click(object sender, RoutedEventArgs e)
        {
            //button for 'selecting input file'
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.RestoreDirectory = true;
            dialog.Filter = "*.txt|*.*";
            //dialog.FilterIndex = 0;
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                ((System.Windows.Controls.Button)sender).Content = "(点击可以再次选择)";
                //InputFileName = dialog.FileName;
                this.InputFileDest.Text = dialog.FileName;
            }
        }

        private void OutputButton_Click(object sender, RoutedEventArgs e)
        {
            //button for 'selecting output file'

            FolderBrowserDialog dialog = new FolderBrowserDialog();
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK &&
                !string.IsNullOrWhiteSpace(dialog.SelectedPath))
            {
                ((System.Windows.Controls.Button)sender).Content = "(点击可以再次选择)";
                //OutputFileName = dialog.FileName;
                this.OutputFileDest.Text = dialog.SelectedPath + "\\Report.txt";
                this.outputdir = dialog.SelectedPath;
            }
        }

        private void Run_Click(object sender, RoutedEventArgs e)
        {
            InputFileName = this.InputFileDest.Text;
            OutputFileName = this.OutputFileDest.Text;
            if (OutputFileName.Length == 0)
            {
                System.Windows.Forms.MessageBox.Show("没有指定输出路径!", "警告！", MessageBoxButtons.OK);
                return;
            }
            string text = "";
            if (this.ModeSelectBox.SelectedIndex == 0)
            {
                //FileStream inputfile = File.OpenRead(InputFileName);
                //FileStream outputfile = File.OpenWrite(OutputFileName);
                text = this.TextCode.Text;
            }
            else
                text = File.ReadAllText(InputFileName);
            List<List<string>> result = this.parser.parse(text);
            File.WriteAllText(OutputFileName, output(result));
            Process.Start("explorer.exe", @outputdir);
        }
    }
}
