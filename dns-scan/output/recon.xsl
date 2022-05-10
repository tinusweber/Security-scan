<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>
  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta name="referrer" content="no-referrer"/>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css" type="text/css" integrity="sha384-VEpVDzPR2x8NbTDZ8NFW4AWbtT2g/ollEzX/daZdW/YvUBlbgVtsxMftnJ84k0Cn" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.0.1/build/styles/default.min.css"/>

        <script src="https://code.jquery.com/jquery-3.3.1.js" integrity="sha384-fJU6sGmyn07b+uD1nMk7/iSb4yvaowcueiQhfVgQuD98rfva8mcr1eSvjchfpMrH" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js" integrity="sha384-rgWRqC0OFPisxlUvl332tiM/qmaNxnlY46eksSZD84t+s2vZlqGeHrncwIRX7CGp" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/1.10.19/js/dataTables.bootstrap.min.js" integrity="sha384-7PXRkl4YJnEpP8uU4ev9652TTZSxrqC8uOpcV1ftVEC7LVyLZqqDUAaq+Y+lGgr9" crossorigin="anonymous"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
        <script src="https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.0.1/build/highlight.min.js"></script>
        <script>hljs.highlightAll();</script>
        <style>
          @media only screen and (min-width:1900px) {
            .container { width: 1800px; }
          }
          .target:before { content: ""; display: block; height: 10px; margin: -20px 0 0; }
          .footer { margin-top:60px; padding-top:60px; width: 100%; height: 180px; background-color: #f5f5f5; }
          .clickable { cursor: pointer; }
          .panel-heading > h3:before { font-family: 'Glyphicons Halflings'; content: "\e114"; padding-right: 1em; }
          .panel-heading.collapsed > h3:before { content: "\e080"; }
          body { --font-family:  "HP Simplified Light", "Helvetica", Arial, sans-serif; --font-family-url:  Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; --font-base:  16px; }
          h1 { text-shadow: 2px 2px Lightgray; text-align: center; }
          table { font-family: Arial, Helvetica, sans-serif; border-collapse: collapse; width: 100%; }
          td, th { border: 1px solid #ddd; padding: 8px; }
          tr:nth-child(even){background-color: #f2f2f2; }
          tr:hover { background-color: #ddd; }
          th { padding-top: 12px; padding-bottom: 12px; text-align: left; background-color: #04AA6D; color: white; border: 1px solid #ddd; }
          #box { border: 1px solid #ddd; padding: 15px; }
          img { display: block; margin-left: auto; margin-right: auto; width: 50%; }
          .nobreak { white-space: nowrap !important; }
          .textcenter{ text-align: center !important; }
          .modal-dialog { width: 90%; height: 90%; padding: 0; overflow-y: initial !important; }
          .modal-content { height: 100%; border-radius: 0; }
          .modal-body{ height: 80vh; overflow-y: auto; }
          tfoot input { width: 100% !important;}
          .nobgcolorth { background-color: transparent !important; border-style: none !important!; }
          .box{ box-shadow: 2px 2px 7px 2px gray; }
          .column { float: left; width: 33.30%; padding: 12px; }
          .row::after { content: ""; clear: both; display: table; }
        </style>
        <title>Scan Report DNS reconnaissance</title>
      </head>
      <body>
        <div class="container-fluid">
          <small>
            <img src="http://www.solbian.nl/logo%20it-zaken.png" alt="it-zaken-logo"/>
          </small>
        </div>
        <div class="container-fluid" style="margin-top:80px !important;">
          <div class="table-responsive">

            <div class="tab-content">
              <div id="recon" class="tab-pane fade in active">

                <p>
                  <!-- Start ip/host-->
                  <div class="table-responsive">
                    <table class="table table-bordered">
                      <h1 id="headers" class="target">Headers</h1>
                    <table id="table-test" class="table table-striped dataTable" role="grid">
                      <thead>
                        <tr>
                          <th class="nobreak textcenter">Scan</th>
                          <th class="nobreak textcenter">Info</th>
                        </tr>
                      </thead>

                      <tbody>
                        <xsl:choose>
                          <xsl:when test="../@moduleName = Headers">
                            <xsl:for-each select="../@dataPair">
                              <tr>
                                <td class="nobreak textcenter">
                                  <xsl:value-of select="dataPair/@dataKey"/>
                                </td>
                                <td class="nobreak textcenter"> 
                                  <xsl:value-of select="dataPair/@dataVal"/>
                                </td>
                              </tr>
                            </xsl:for-each>
                          </xsl:when>
                        </xsl:choose>
                      </tbody>
                    </table>
                  </table>
                </div>
                <script>
                    $(document).ready(function() {
                      $('#table-overview').DataTable();
                    });
                </script>
                <hr/>
              </p>
            </div>
          </div>
        </div>
      </div>
    </body>
  </html>
</xsl:template>
</xsl:stylesheet>