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
            Dictionary<String, List<String>> Rules_mapping = new Dictionary<string, List<string>>();
            Dictionary<String, HashSet<String>> FIRSTVT = new Dictionary<string, HashSet<string>>(), LASTVT = new Dictionary<string, HashSet<string>>();
            List<myitem> stack = new List<myitem>();
            Dictionary<string, string> SymbolTable = new Dictionary<string, string>();
            List<Tuple<List<myitem>, int>> History = new List<Tuple<List<myitem>, int>>();
            List<String> commands = new List<string>();
            String sourcetext="";
            Dictionary<Tuple<String, String>, int> Matrix = new Dictionary<Tuple<string, string>, int>();
            //0 - <,1 - >,2 - =,not exist-unknown
            String[] buf = null;
            String[] sentence = null;
            String original = "";
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
                buf = sourcetext.Split("\r\n".ToCharArray(),StringSplitOptions.RemoveEmptyEntries);
                
            }
            private Boolean rules_converge()
            {
                foreach(var item in buf)
                {
                    var tmp = item.Split(' ');
                    if (!tmp[1].Equals("::="))
                        return false;
                    int length = tmp.Length;
                    if (!Rules_mapping.ContainsKey(tmp[0]))
                        Rules_mapping.Add(tmp[0], new List<string>());
                    for (int index = 2;index<length;index++)
                    {
                        Rules_mapping[tmp[0]].Add(tmp[index]);
                        if (index > 2)
                            if (SymbolTable[tmp[index]].Equals("VN") && SymbolTable[tmp[index - 1]].Equals("VN"))
                                return false;
                    }
                    Rules_mapping[tmp[0]].Add("|");
                }
                return true;
            }
            public String parse(String text)
            {
                sourcetext = text.ToString();
                segmentSource();
                find_all_vn_and_build_sym_table(); //also build rules
                //check_OG_rules();
                if (error_status == -1)
                    return error_msg;
                Boolean flag = rules_converge();
                if (!flag)
                    return "Not an OG!\n";
                find_first_vt();
                find_last_vt();
                build_matrix();
                if (error_status == -1)
                    return error_msg;
                
                StringBuilder sb = new StringBuilder();
                sb.Append("VT集\n");
                foreach(var item in SymbolTable)
                {
                    if (item.Value.Equals("VT"))
                        sb.Append(item.Key+" ");
                }
                sb.Append("\n");
                sb.Append("产生式\n");
                foreach(var item in SymbolTable)
                {
                    if (item.Value.Equals("VT"))
                        continue;
                    sb.Append(item.Key + "::= ");
                    int length = Rules_mapping[item.Key].Count;
                    for (int index = 0;index<length-1;index++)
                    {
                        sb.Append(Rules_mapping[item.Key][index]+" ");
                    }
                    sb.Append("\n");
                }
                sb.Append("FIRSTVT\n");
                foreach(var item in FIRSTVT)
                {
                    sb.Append(item.Key + ":");
                    foreach(var item2 in item.Value)
                    {
                        sb.Append(item2 + " ");
                    }
                    sb.Append("\n");
                }
                sb.Append("LASTVT\n");
                foreach (var item in LASTVT)
                {
                    sb.Append(item.Key + ":");
                    foreach (var item2 in item.Value)
                    {
                        sb.Append(item2 + " ");
                    }
                    sb.Append("\n");
                }
                sb.Append("算符优先关系表\n");
                for (int i = 0; i < 10; i++)
                    sb.Append(" ");
                sb.Append("|");
                var vts = new List<String>();
               // var vns = new List<String>();
                foreach (var item in SymbolTable)
                {
                    if (item.Value.Equals("VT") && !item.Key.Equals("#"))
                    { vts.Add(item.Key);
                        sb.Append(item.Key);
                        int len = item.Key.Length;
                        while (len<10)
                        {
                            sb.Append(" ");
                            len++;
                        }
                        sb.Append("|");
                    }
                    //else
                      //  vns.Add(item.Key);
                }
                //vts.Add("#");
                sb.Append("\n");
                foreach(var item in vts)
                {
                    sb.Append(item);
                    int len = item.Length;
                    while (len < 10)
                    {
                        sb.Append(" ");
                        len++;
                    }
                    sb.Append("|");
                    foreach (var item2 in vts)
                    {
                        var now_item = new Tuple<string, string>(item, item2);
                        if (Matrix.ContainsKey(now_item))
                        {
                            if (Matrix[now_item] == 0)
                                sb.Append("<");
                            else if (Matrix[now_item] == 1)
                                sb.Append(">");
                            else if (Matrix[now_item] == 2)
                                sb.Append("=");
                        }
                        else
                            sb.Append(" ");
                        int len2 = 1;
                        while (len2 < 10)
                        {
                            sb.Append(" ");
                            len2++;
                        }
                        sb.Append("|");
                    }
                    sb.Append("\n");
                }


                // clean_work();
                return sb.ToString();
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
                bool flag = false;
                foreach(String e in buf)
                {
                    List<myitem> now = new List<myitem>();
                    //int position = e.IndexOf("::=");
                    //string s = e.Substring(0, position);
                    String[] strbuf = e.Split(' ');
                    string s = strbuf[0];
                    if (!flag)
                    {
                        original = new string(s.ToCharArray());
                        flag = true;
                    }
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
                    stack.RemoveAt(stack_count - 1);
                    string V = now.content;
                    string b = now.attribute;
                    foreach (var list in Rules)
                    {
                        if (list.Count>=2)
                        {
                            if (list[1].content.Equals(V) && !FIRSTVT[list[0].content].Contains(b))
                            {
                                firstvt_insert(list[0].content, b);
                            }
                        }
                    }
                    

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
                    stack.RemoveAt(stack_count - 1);
                    string V = now.content;
                    string b = now.attribute;
                    foreach (var list in Rules)
                    {
                        if (list.Count >= 2)
                        {
                            if (list[list.Count-1].content.Equals(V) &&!LASTVT[list[0].content].Contains(b))
                            {
                                lastvt_insert(list[0].content, b);
                            }
                        }
                    }
                    

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
                                            error_msg = "Not an OPG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
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
                                            error_msg = "Not an OPG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
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
                                        error_msg = "Not an OPG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
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
                                            error_msg = "Not an OPG: Conflict Priority Order Over" + now_item.Item1 + " and " + now_item.Item2;
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
                        Matrix.Add(new Tuple<string, string>("#",item.Key),0);
                        Matrix.Add(new Tuple<string, string>(item.Key,"#"), 1);
                    }
                }
                Matrix.Add(new Tuple<string, string>("#","#"),1);
            }
            private int search(List<myitem> stack_tmp,String symbol)
            { 
                int length = stack_tmp.Count;
                string symbol_tmp = symbol;
                for (int i=length-1;i>=0;i--)
                {
                    if (stack_tmp[i].attribute.Equals("VN"))
                        continue;
                    var now_item = new Tuple<String, String>(stack_tmp[i].content, symbol_tmp);
                    if (!Matrix.ContainsKey(now_item))
                        return -1;
                    if (Matrix[now_item] == 0)
                        return i+1;
                    symbol_tmp = stack_tmp[i].content;
                }
                return -1;
            }
            private int search(List<myitem> stack_tmp, String symbol,int limit)
            {
                int length = stack_tmp.Count;
                string symbol_tmp = symbol;
                for (int i = limit-1; i >= 0; i--)
                {
                    if (stack_tmp[i].attribute.Equals("VN"))
                        continue;
                    var now_item = new Tuple<String, String>(stack_tmp[i].content, symbol_tmp);
                    if (!Matrix.ContainsKey(now_item))
                        return -1;
                    if (Matrix[now_item] == 0)
                        return i+1;
                    symbol_tmp = stack_tmp[i].content;
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
                var last_status = History[count-1];
                if (last_status.Item1.Count == 2 && last_status.Item1[1].content.Equals(original))
                    if (last_status.Item2 == this.sentence.Length-1)
                    return 0;
                if (last_status.Item2 >= this.sentence.Length)
                    return -1;
                int nowvt = search_vt(last_status.Item1);
                if (nowvt < 0) return -1;
                string nowsymbol = this.sentence[last_status.Item2];
                string stacksymbol = last_status.Item1[nowvt].content;
                if (nowsymbol != "#")
                {
                    if (!SymbolTable.ContainsKey(nowsymbol)) return -1;
                    if (!SymbolTable[nowsymbol].Equals("VT")) return -1;
                }
                var now_item = new Tuple<String, String>(stacksymbol, nowsymbol);
                if (!Matrix.ContainsKey(now_item)) return -1;
                if (Matrix[now_item] != 1)
                {
                    var stack_tmp = new List<myitem>(last_status.Item1);
                    //Console.WriteLine("Shift");
                    //Console.WriteLine(nowsymbol);
                    //Console.WriteLine(now_item);
                    stack_tmp.Add(new myitem(nowsymbol, SymbolTable[nowsymbol]));
               
                    History.Add(new Tuple<List<myitem>, int>(stack_tmp, last_status.Item2 + 1));
                    commands.Add("< Shift");
                    int res = work();
                    if (res < 0)
                    {
                        int length = History.Count();
                        History.RemoveAt(length - 1);
                        commands.RemoveAt(length - 1);
                    }
                    else return 0;
                }
                else
                {
                    //Console.WriteLine("Reduce");
                    //Console.WriteLine(nowsymbol);
                    //Console.WriteLine(now_item);
                    int flag = Matrix[now_item];
                    int reduce_position = last_status.Item1.Count;
                    //while (reduce_position >= 0)
                    {
                        reduce_position = search(last_status.Item1, nowsymbol, reduce_position);
                        //Console.WriteLine(reduce_position);
                        if (reduce_position < 0) return -1;
                        int length = last_status.Item1.Count;
                        List<myitem> pattern = new List<myitem>();
                        List<myitem> source = new List<myitem>();
                        for (int i = 0; i < (reduce_position==0?1:reduce_position); i++)
                            source.Add(last_status.Item1[i]);
                        for (int i = reduce_position==0?1:reduce_position; i < length; i++)
                        {
                            pattern.Add(last_status.Item1[i]);
                        }
                        //Console.WriteLine(pattern);
                        //Console.WriteLine(source);
                        List<List<myitem>> candidate_status = getAllCandidate(pattern, source);
                        //Console.WriteLine(candidate_status);
                        for (int i = 0; i < candidate_status.Count; i++)
                        {
                            History.Add(new Tuple<List<myitem>, int>(candidate_status[i], last_status.Item2));
                            if (flag == 1)
                                commands.Add("> Reduce");
                            else
                                commands.Add("= Reduce");
                            int res = work();
                            if (res < 0)
                            {
                                int tmp = History.Count;
                                History.RemoveAt(tmp - 1);
                                commands.RemoveAt(tmp - 1);
                            }
                            else return 0;
                        }
                    }
                }
                return -1;
            }
            public int analysis(string sentence)
            {
                var stack_tmp = new List<myitem>();
                stack_tmp.Add(new myitem("#","VT"));
                History.Clear();
                History.Add(new Tuple<List<myitem>, int>(stack_tmp, 0));
                commands.Clear();
                commands.Add("< Shift");
                sentence = sentence + " #";
                this.sentence = sentence.Split(' ');
                int res = work();
                return res;
            }
            public List<List<String>> output()
            {
                var res = new List<List<String>>();
                int count = 0;
                commands.Add("< Reduce");
                foreach (var item in History)
                {
                    //res.Add(new List<string>());
                    var tmp = new List<String>();
                    foreach (var item2 in item.Item1)
                    {
                        tmp.Add(item2.content);
                    }
                    tmp.Add("\r\n");
                    tmp.Add(sentence[item.Item2]);
                    tmp.Add("\r\n");
                    for (int index = item.Item2+1;index<sentence.Length;index++)
                    {
                        tmp.Add(sentence[index]);
                    }
                    tmp.Add("\r\n");
                    tmp.Add(commands[count+1].Split(' ')[0]);
                    tmp.Add("\r\n");
                    tmp.Add(commands[count+1].Split(' ')[1]);
                    tmp.Add("\r\n");
                    count++;
                    res.Add(tmp);
                }
                return res;
            }
            public void clean_work()
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
                Rules_mapping.Clear();
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

        private string zero_padding(string s,int num)
        {
            int len = s.Length;
            StringBuilder sb = new StringBuilder(s);
            while (sb.Length<num)
            {
                sb.Append(" ");
            }
            return sb.ToString();
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
            this.Pb.Minimum = 0;
            this.Pb.Value = 0;
            if (this.ModeSelectBox.SelectedIndex == 0)
            {
                //FileStream inputfile = File.OpenRead(InputFileName);
                //FileStream outputfile = File.OpenWrite(OutputFileName);
                text = this.TextCode.Text;
            }
            else
                text = File.ReadAllText(InputFileName);
            try
            {
                var grammar = text.Split("&&&&".ToCharArray(),StringSplitOptions.RemoveEmptyEntries)[0];
                // var sentence_buf = text.Split("\r\n\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries)[1];
                var sentence_buf = text.Split("&&&&".ToCharArray(), StringSplitOptions.RemoveEmptyEntries)[1].Trim("\r\n".ToCharArray());
                String result = this.parser.parse(grammar);
                File.WriteAllText(OutputFileName, result);
                //String warning = "";
                if (result.Equals("Not an OG!\n") || this.parser.error_status == -1)
                {
                    System.Windows.Forms.MessageBox.Show(result, "警告！", MessageBoxButtons.OK);
                    return;
                }

                var sentences = sentence_buf.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
                StringBuilder sb = new StringBuilder(result);
                sb.Append("句子分析\n");
                int count = -1;
                int[] types = { 10, 30, 10, 30, 10, 10 };
                this.Pb.Maximum = sentences.Length;
                foreach (var item in sentences)
                {
                    count += 1;
                    sb.Append(count.ToString() + " " + item+"\n");
                    sb.Append(zero_padding("序号",types[0]-2)+"|"+zero_padding("栈", types[1]-2) +"|"+zero_padding("现在字符", types[2]-4) +"|"+zero_padding("剩余字符", types[3]-4) +"|"+zero_padding("大小关系", types[4]-4) +"|"+zero_padding("动作", types[5]-4) +"\n");
                    var flag = this.parser.analysis(item);
                    if (flag < 0)
                        sb.Append("Failure at sentence:" + item + "\n");
                    else
                    {
                        var output = this.parser.output();
                        int index = 0;
                        while (index < output.Count)
                        {
                            int index2 = 0;
                            StringBuilder tmp = new StringBuilder();
                            sb.Append(zero_padding(index.ToString(),types[0]));
                            int type = 1;
                            while (index2 < output[index].Count)
                            {
                                if (output[index][index2].Equals("\r\n"))
                                {
                                    sb.Append(zero_padding(tmp.ToString(), types[type])+"|");
                                    tmp.Clear();
                                    type += 1;
                                }
                                else
                                {
                                    tmp.Append(output[index][index2]);
                                }
                                index2++;
                            }
                            sb.Append("\n");
                            index++;
                        }
                    }
                    this.Pb.Value += 1;
                    
                }
                File.WriteAllText(OutputFileName, sb.ToString());
                Process.Start("explorer.exe", @outputdir);
                this.parser.clean_work();
            }
            catch(Exception ex)
            {
                System.Windows.Forms.MessageBox.Show("输入格式有误!\n"+ex.Message+"\r\n"+ex.Data.ToString()+ex.StackTrace, "警告！", MessageBoxButtons.OK);
                //throw ex;
                return;
            }
            
        }

       
    }
}
