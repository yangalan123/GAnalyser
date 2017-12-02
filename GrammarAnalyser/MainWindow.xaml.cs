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
            List<List<myitem>> Rules = new List<List<myitem>>();
            Dictionary<String, HashSet<String>> FIRSTVT = new Dictionary<string, HashSet<string>>(), LASTVT = new Dictionary<string, HashSet<string>>();
            List<myitem> stack = new List<myitem>();
            Dictionary<string, string> SymbolTable = new Dictionary<string, string>();
            String sourcetext="";
            Dictionary<Tuple<String, String>, int> Matrix = new Dictionary<Tuple<string, string>, int>();
            //0-<,1->,not exist-unknown
            String[] buf = null;
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
                        if (list[1].attribute=="VT")
                        {
                            firstvt_insert(list[0].content, list[1].content);
                        }
                    }
                    if (list.Count>=3)
                    {
                        if (list[2].attribute == "VT" && list[1].attribute == "VN")
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
                        if (list[list_count-1].attribute == "VT")
                        {
                            lastvt_insert(list[0].content, list[list_count-1].content);
                        }
                    }
                    if (list.Count >= 3)
                    {
                        if (list[list_count-2].attribute == "VT" && list[list_count-1].attribute == "VN")
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
                          
                            if (list[i].attribute=="VN" && list[i-1].attribute=="VT")
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
                            else if (list[i].attribute == "VT" && list[i - 1].attribute == "VN")
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
                        }
                    }
                }
            }
            private void
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
