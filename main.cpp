#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#define MAX_CMD 4096
 /**********
* 喵喵控制台v1.6 更新于2026/07/03
*
* 喵喵控制台项目：CMD终端替代版，拒绝执行任何删文件的危险命令！
* 有效预防手贱或误操作（当然，真要毁系统我也拦不住你）
* 注：没有拦截format和diskpart，我这里直接把它俩源文件删了。
*
* v1.1更新说明：增加对分号的拦截
* v1.2更新说明：直接拦截所有标点 
* v1.3更新说明：彻底重写逻辑，危险命令边界匹配拦截
* v1.4更新说明：修复注释歧义、增加%变量拦截
* v1.5更新说明：新增独立bat检测，执行前三次强制确认提问
* v1.6更新说明：重新编辑了危险命令列表（多达20种） 
**********/
const char *DANGEROUS[] = {
    "del",         // 1.禁止删除文件 
	"rd",          // 2.禁止删除文件夹 
	"rmdir",       // 3.del的别名 
	"erase",       // 4.erase的别名 
	"rm",          // 5.Linux删除，备用禁用
    "bash",        // 6.Linux终端，备用禁用  
	"cmd",         // 7.禁止打开cmd自身 
	"conhost",     // 8.禁止打开cmd自身 
	"powershell",  // 9.禁止在这里使用powershell 
	"wsl",         // 10.禁止使用自带Linux终端 
	"mshta",       // 11.禁止不明脚本 
	"net",         // 12.禁止用户控制 
	"reg",         // 13.禁止命令行编辑注册表
	"bcdedit",     // 14.禁止操纵引导
	"bcdboot",     // 15.禁止重建引导（如有需要使用PE）
	"bootsect",    // 16.禁止写MBR引导
	"takeown",     // 17.禁止操纵权限
	"icacls",      // 18.禁止操纵权限
	"mountvol",    // 19.禁止操纵卸载卷 
	"cipher",      // 20.禁止空闲擦除 
	NULL};

/* 去掉首尾空白 */
void trim(char *s)
{
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) { *s = 0; return; }

    char *end = p + strlen(p) - 1;
    while (end > p && isspace((unsigned char)*end)) *end-- = 0;
    memmove(s, p, strlen(p) + 1);
}

/*
 * 核心函数：检查独立裸敏感词
 * 规则：危险单词左右两侧不能是字母/数字，视为独立危险指令直接拦截
 */
int contains_dangerous_command(const char *cmd)
{
    char buf[MAX_CMD];
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    // 拦截CMD变量语法 %xxx%，防止变量拼接危险命令
    if (strstr(buf, "%"))
        return 1;
    /* 转小写 */
    for (char *p = buf; *p; ++p)
        *p = (char)tolower(*p);
    /* 移除 ^ 转义符 */
    char *w = buf;
    for (char *r = buf; *r; ++r) {
        if (*r != '^') *w++ = *r;
    }
    *w = '\0';
    /* 扫描危险词 */
    for (int i = 0; DANGEROUS[i]; ++i) {
        const char *word = DANGEROUS[i];
        size_t wlen = strlen(word);
        for (char *p = buf; *p; ++p) {
            if (strncmp(p, word, wlen) != 0)
                continue;
            /* 左边界：左边是字母或数字才放行 */
            int left_ok = 1;
            if (p > buf && isalnum((unsigned char)p[-1]))
                left_ok = 0;
            /* 右边界：右边是是字母或数字才放行 */
            int right_ok = 1;
            if (p[wlen] && isalnum((unsigned char)p[wlen]))
                right_ok = 0;
            // 左右都不是字母数字，是独立危险命令，拦截
            if (left_ok && right_ok) {
                return 1;
            }
        }
    }
    return 0;
}

// 复用边界规则，检测命令中是否存在独立单词 bat
int has_bat_word(const char *cmd)
{
    char buf[MAX_CMD];
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    // 统一小写、移除^转义，和危险词检测逻辑保持一致
    for (char *p = buf; *p; ++p)
        *p = (char)tolower(*p);
    char *w = buf;
    for (char *r = buf; *r; ++r) {
        if (*r != '^') *w++ = *r;
    }
    *w = '\0';

    const char *target = "bat";
    size_t tlen = strlen(target);
    for (char *p = buf; *p; ++p)
    {
        if (strncmp(p, target, tlen) != 0)
            continue;

        int left_ok = 1;
        if (p > buf && isalnum((unsigned char)p[-1]))
            left_ok = 0;

        int right_ok = 1;
        if (p[tlen] && isalnum((unsigned char)p[tlen]))
            right_ok = 0;

        if (left_ok && right_ok)
            return 1;
    }
    return 0;
}

int main(void)
{
    SetConsoleTitle("喵喵控制台");
    printf("JiahongMeow Console [版本1.6]\n");
    printf("(c) 嘉鸿喵工作室。保留所有权利。\n");
    printf("虽然这里有保护，但还是请你对输入的命令负责喵！\n\n");
    char cmd[MAX_CMD];
    char inputBuf[64];
    printf("MeowCMD> ");
    while (fgets(cmd, sizeof(cmd), stdin)) {
        trim(cmd);
        if (_stricmp(cmd, "exit") == 0)
            break;

        // 第一步：检测危险指令，直接拦截
        if (contains_dangerous_command(cmd)) {
            printf("嘉鸿喵不许你执行这个：%s\n", cmd);
        }
        else if (has_bat_word(cmd))
        {
            // 存在独立bat，三次确认流程
            int pass = 1;
            // 第一次提问
            printf("\n注意！你似乎即将执行一个批处理文件喵。你知道你在干什么喵？请回答“我知道”以继续喵。\n请回答：");
            fgets(inputBuf, sizeof(inputBuf), stdin);
            trim(inputBuf);
            if (strcmp(inputBuf, "我知道") != 0)
            {
                pass = 0;
            }

            if (pass)
            {
                // 第二次提问
                printf("\n你确认你看过你要执行的批处理文件的代码逻辑喵？请回答“我确认”以继续喵。\n请回答：");
                fgets(inputBuf, sizeof(inputBuf), stdin);
                trim(inputBuf);
                if (strcmp(inputBuf, "我确认") != 0)
                {
                    pass = 0;
                }
            }

            if (pass)
            {
                // 第三次提问
                printf("\n这是最后一次提醒喵！你愿意为自己执行这个批处理的结果负责喵？请回答“我愿意”以继续喵。\n请回答：");
                fgets(inputBuf, sizeof(inputBuf), stdin);
                trim(inputBuf);
                printf("\n") ; 
                if (strcmp(inputBuf, "我愿意") != 0)
                {
                    pass = 0;
                }
            }

            if (!pass)
            {
                printf("对不起，嘉鸿喵不能让你继续执行喵。\n");
            }
            else
            {
                // 三次全部答对，执行命令
                system(cmd);
            }
        }
        else
        {
            // 无危险、无bat，直接执行
            system(cmd);
        }
        printf("\nMeowCMD> ");
    }
    return 0;
}
